using Automata;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text;

public sealed class InteractiveLaunchWorker : BackgroundService
{
    private static readonly ILogger _logger = LogManager.CreateLogger(nameof(InteractiveLaunchWorker));
    private readonly IConfiguration _cfg;

    private static readonly string LogDir = Path.Combine(AppContext.BaseDirectory, "logs");
    private static StreamWriter? _sessionWriter;       // For automatic logging
    private const string Host = "127.0.0.1";
    private const int Port = 5000;

    private static void InitLog()
    {
        Directory.CreateDirectory(LogDir);

        // Session log (timestamped)
        string sessionLogFile = Path.Combine(LogDir, $"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
        _sessionWriter?.Dispose();
        _sessionWriter = new StreamWriter(sessionLogFile, false, Encoding.UTF8) { AutoFlush = true };
    }
    public static void LogToGui(string message)
    {
        try
        {
            using (TcpClient client = new TcpClient())
            {
                client.Connect(Host, Port); // GUI must be running
                using (NetworkStream stream = client.GetStream())
                {
                    message = "WORKER: " + message;
                    byte[] data = Encoding.UTF8.GetBytes(message + Environment.NewLine);
                    stream.Write(data, 0, data.Length);
                }
            }
        }
        catch
        {
            // silently ignore if GUI is not listening
        }
    }
    private static void LogToFile(string message)
    {
        try
        {
            string timestampedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
            _sessionWriter?.WriteLine(timestampedMessage);
            LogToGui(timestampedMessage);
        }
        catch
        {
            // ignore logging errors
        }
    }

    public InteractiveLaunchWorker(ILogger<InteractiveLaunchWorker> log, IConfiguration cfg)
    {
        _cfg = cfg;
    }

    // ---------- Protocol models ----------
    private sealed record LaunchRequest(
        string exe,
        string? args,
        string? workDir,
        int? sessionId,
        int timeoutSec = 30,
        string? userName = null,
        bool loadUserProfile = true,
        bool isSilent = true
    );

    private sealed record LaunchResponse(bool ok, int pid, string? error = null);

    // ---------- Config (with sane defaults) ----------
    private string PipeName => _cfg["Launcher:PipeName"] ?? "Automation.InteractiveLauncher.v1";
    private bool EnablePipe => GetBool("Launcher:EnablePipe", true);

    private bool EnableTcp => GetBool("Launcher:EnableTcp", true);
    private IPAddress TcpBindAddress => IPAddress.Parse(_cfg["Launcher:TcpBindAddress"] ?? "127.0.0.1");
    private int TcpPort => int.TryParse(_cfg["Launcher:TcpPort"], out var p) ? p : 49321;

    private bool GetBool(string key, bool def)
    {
        return _cfg.GetValue<bool?>(key) ?? def;
    }


    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        bool enableTcp = true;
        bool enablePipe = true;
        var tcpBindAddress = IPAddress.Loopback; // 127.0.0.1
        int tcpPort = 49321;
        string pipeName = "Automation.InteractiveLauncher.v1";

        InitLog();
        LogToFile("OogaBooga");
        LogToFile("InteractiveLaunchWorker starting...");
        LogToFile($"InteractiveLauncher starting. TCP:{EnableTcp} Pipe:{EnablePipe} on {TcpBindAddress}:{tcpPort}");

        var tasks = new List<Task>(2);

        if (EnablePipe)
            tasks.Add(RunPipeServerLoopAsync(stoppingToken));

        if (EnableTcp)
            tasks.Add(RunTcpServerAsync(TcpBindAddress, TcpPort, stoppingToken));

        await Task.WhenAll(tasks);
        LogToFile("InteractiveLauncher exiting.");
    }

    // ===================== TCP SERVER =====================
    private async Task RunTcpServerAsync(IPAddress ip, int port, CancellationToken ct)
    {
        var listener = new TcpListener(ip, port);
        listener.Start();
        LogToFile($"TCP listening on {ip}:{port}");

        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                _ = Task.Run(() => HandleTcpClientAsync(client, ct));
            }
        }
        finally
        {
            try { listener.Stop(); } catch { /* ignore */ }
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken ct)
    {
        LogToGui("TCP Client Triggered");
        using var _ = client;
        client.NoDelay = true;

        using var ns = client.GetStream();
        using var reader = new StreamReader(ns, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        using var writer = new StreamWriter(ns, new UTF8Encoding(false), bufferSize: 4096, leaveOpen: true) { AutoFlush = true };

        var jsonOpts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        try
        {
            // NDJSON: read exactly one line
            string? json = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(json))
            {
                await writer.WriteLineAsync("{\"ok\":false,\"pid\":0,\"error\":\"Empty request.\"}");
                LogToGui("{\"ok\":false,\"pid\":0,\"error\":\"Empty request.\"}");
                return;
            }

            var req = JsonSerializer.Deserialize<LaunchRequest>(json, jsonOpts)
                      ?? throw new InvalidOperationException("Invalid JSON payload.");

            if (string.IsNullOrWhiteSpace(req.exe) || !File.Exists(req.exe))
            {
                await writer.WriteLineAsync("{\"ok\":false,\"pid\":0,\"error\":\"Executable not found.\"}");
                LogToGui("{\"ok\":false,\"pid\":0,\"error\":\"Executable not found.\"}");
                return;
            }

            int targetSession = req.sessionId ?? unchecked((int)WTSGetActiveConsoleSessionId());
            if (targetSession == -1)
            {
                await writer.WriteLineAsync("{\"ok\":false,\"pid\":0,\"error\":\"No active console session.\"}");
                LogToGui("{\"ok\":false,\"pid\":0,\"error\":\"No active console session.\"}");
                return;
            }

            int pid = LaunchInSession(
                sessionId: targetSession,
                exePath: req.exe,
                arguments: req.args ?? "",
                workingDir: string.IsNullOrWhiteSpace(req.workDir) ? Path.GetDirectoryName(req.exe)! : req.workDir!,
                timeout: TimeSpan.FromSeconds(Math.Max(0, req.timeoutSec)),
                loadProfile: req.loadUserProfile,
                profileUserName: req.userName,
                isSilent: req.isSilent);

            await writer.WriteLineAsync($"{{\"ok\":true,\"pid\":{pid}}}");
            LogToGui($"{{\"ok\":true,\"pid\":{pid}}}");
        }
        catch (Exception ex)
        {
            // Ensure the response is one JSON line
            await writer.WriteLineAsync($"{{\"ok\":false,\"pid\":0,\"error\":{JsonSerializer.Serialize(ex.Message)}}}");
            // LogToFile(ex + " TCP request failed.");
        }
    }

    // ===================== PIPE SERVER (NDJSON) =====================
    private async Task RunPipeServerLoopAsync(CancellationToken ct)
    {
        LogToFile($"Pipe listening on \\\\.\\pipe\\{PipeName}");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var server = CreateSecuredPipe();
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                _ = HandlePipeClientAsync(server, ct); // one-shot per connection
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                // LogToFile(ex + " Pipe server loop error.");
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
            }
        }
    }

    private static NamedPipeServerStream CreateSecuredPipe()
    {
        // If you kept the AccessControl package, this version enforces Admins+SYSTEM only.
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.SetOwner(system);

        return NamedPipeServerStreamAcl.Create(
            pipeName: "Automation.InteractiveLauncher.v1",
            direction: PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            transmissionMode: PipeTransmissionMode.Byte,
            options: PipeOptions.Asynchronous,
            inBufferSize: 64 * 1024,
            outBufferSize: 64 * 1024,
            pipeSecurity: ps,
            inheritability: HandleInheritability.None,
            additionalAccessRights: PipeAccessRights.ReadWrite);
    }

    private async Task HandlePipeClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var pipeRef = pipe;
        var jsonOpts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        try
        {
            using var reader = new StreamReader(pipe, new UTF8Encoding(false), false, 4096, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

            // 🔄 NDJSON: read exactly one line (client must send '\n')
            string? json = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(json))
            {
                await JsonSerializer.SerializeAsync(writer.BaseStream, new LaunchResponse(false, 0, "Empty request."), jsonOpts, ct);
                await writer.FlushAsync().ConfigureAwait(false);
                return;
            }

            var req = JsonSerializer.Deserialize<LaunchRequest>(json, jsonOpts)
                      ?? throw new InvalidOperationException("Invalid JSON payload.");

            if (string.IsNullOrWhiteSpace(req.exe) || !File.Exists(req.exe))
            {
                await JsonSerializer.SerializeAsync(writer.BaseStream, new LaunchResponse(false, 0, "Executable not found."), jsonOpts, ct);
                await writer.FlushAsync().ConfigureAwait(false);
                return;
            }

            int targetSession = req.sessionId ?? unchecked((int)WTSGetActiveConsoleSessionId());
            if (targetSession == -1)
            {
                await JsonSerializer.SerializeAsync(writer.BaseStream, new LaunchResponse(false, 0, "No active console session."), jsonOpts, ct);
                await writer.FlushAsync().ConfigureAwait(false);
                return;
            }

            int pid = LaunchInSession(
                sessionId: targetSession,
                exePath: req.exe,
                arguments: req.args ?? "",
                workingDir: string.IsNullOrWhiteSpace(req.workDir) ? Path.GetDirectoryName(req.exe)! : req.workDir!,
                timeout: TimeSpan.FromSeconds(Math.Max(0, req.timeoutSec)),
                loadProfile: req.loadUserProfile,
                profileUserName: req.userName);

            await JsonSerializer.SerializeAsync(writer.BaseStream, new LaunchResponse(true, pid), jsonOpts, ct);
            await writer.FlushAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* stopping */ }
        catch (Exception ex)
        {
            // LogToFile(ex + " Pipe request failed.");
            try
            {
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
                await JsonSerializer.SerializeAsync(writer.BaseStream, new LaunchResponse(false, 0, ex.Message), jsonOpts, ct);
                await writer.FlushAsync().ConfigureAwait(false);
            }
            catch { /* ignore */ }
        }
    }

    // ===================== PROCESS LAUNCH CORE =====================
    // Reuse your existing P/Invoke + LaunchInSession implementation.
    // (Below are the signatures used earlier; keep your working versions.)

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("Wtsapi32.dll", SetLastError = true)] private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        TOKEN_ACCESS dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType,
        out IntPtr phNewToken);

    [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);
    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer, uint sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);
    [DllImport("Wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr pMemory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr hObject);

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint CREATE_NO_WINDOW = 0x08000000; 

    private enum TOKEN_TYPE : int { TokenPrimary = 1, TokenImpersonation }
    private enum SECURITY_IMPERSONATION_LEVEL : int { Anonymous, Identification, Impersonation, Delegation }

    [Flags]
    private enum TOKEN_ACCESS : uint
    {
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_QUERY = 0x0008,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public uint cb;
        public string? lpReserved;
        public string? lpDesktop;  // "winsta0\\default"
        public string? lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    private enum WTS_INFO_CLASS
    {
        WTSUserName = 5, // we only use username helper
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROFILEINFO
    {
        public uint dwSize;
        public uint dwFlags;
        public string? lpUserName;
        public string? lpProfilePath;
        public string? lpDefaultPath;
        public string? lpServerName;
        public string? lpPolicyPath;
        public IntPtr hProfile;
    }

    private static string? GetUserNameFromSession(int sessionId)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, (uint)sessionId, WTS_INFO_CLASS.WTSUserName, out var buf, out _))
            return null;
        try { return Marshal.PtrToStringUni(buf); }
        finally { if (buf != IntPtr.Zero) WTSFreeMemory(buf); }
    }

    private int LaunchInSession(int sessionId, string exePath, string arguments, string workingDir, TimeSpan timeout, bool loadProfile, string? profileUserName, bool isSilent = true)
    {
        if (!WTSQueryUserToken((uint)sessionId, out var userToken))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WTSQueryUserToken failed.");

        IntPtr primary = IntPtr.Zero;
        IntPtr env = IntPtr.Zero;
        var si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>(), lpDesktop = "winsta0\\default" };
        var pi = new PROCESS_INFORMATION();
        var profile = new PROFILEINFO();

        try
        {
            var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>() };
            bool dup = DuplicateTokenEx(
                userToken,
                TOKEN_ACCESS.TOKEN_ASSIGN_PRIMARY | TOKEN_ACCESS.TOKEN_DUPLICATE | TOKEN_ACCESS.TOKEN_QUERY | TOKEN_ACCESS.TOKEN_ADJUST_DEFAULT | TOKEN_ACCESS.TOKEN_ADJUST_SESSIONID,
                ref sa,
                SECURITY_IMPERSONATION_LEVEL.Identification,
                TOKEN_TYPE.TokenPrimary,
                out primary);

            if (!dup)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed.");

            if (loadProfile)
            {
                profile.dwSize = (uint)Marshal.SizeOf<PROFILEINFO>();
                profile.lpUserName = profileUserName ?? GetUserNameFromSession(sessionId) ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(profile.lpUserName))
                {
                    if (!LoadUserProfile(primary, ref profile))
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "LoadUserProfile failed.");
                }
            }

            if (!CreateEnvironmentBlock(out env, primary, false))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock failed.");

            string cmdLine = $"\"{exePath}\" {(string.IsNullOrWhiteSpace(arguments) ? "" : arguments)}";
            uint flags;
            if (!isSilent)
            {
                flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;
            }
            else
            {
                flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
            }

            bool ok = CreateProcessAsUser(
                primary,
                null,
                cmdLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                flags,
                env,
                workingDir,
                ref si,
                out pi);

            if (!ok)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser failed.");

            if (timeout > TimeSpan.Zero)
                WaitForSingleObject(pi.hProcess, 0);

            return unchecked((int)pi.dwProcessId);
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (profile.hProfile != IntPtr.Zero) UnloadUserProfile(primary == IntPtr.Zero ? userToken : primary, profile.hProfile);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }
}