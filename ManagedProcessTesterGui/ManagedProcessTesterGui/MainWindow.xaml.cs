using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using Newtonsoft.Json;   // <-- use Json.NET
using System.Collections.Generic;
using System.IO;
using System.Net;
using Microsoft.Win32; // for OpenFileDialog
using System.ServiceProcess;

namespace ManagedProcessTesterGui
{
    public partial class MainWindow : Window
    {
        string _txtFilePath;
        List<Task> _tasks = new List<Task>();

        private TcpListener _listener;
        private bool _listening = false;
        private readonly int _port = 5000; // static port

        private readonly string _logFilePath;

        public MainWindow()
        {
            // Create logs directory if it doesn't exist
            string logsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(logsDir);

            // Create timestamped log file
            _logFilePath = Path.Combine(logsDir, $"log_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.txt");
            File.WriteAllText(_logFilePath, $"Log started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");

            StartService();
            InitializeComponent();
            StartListening();
        }

        // ----- Start the Service ----

        public static void StartService()
        {
            string serviceName = "InteractiveLauncher";

            try
            {
                ServiceController sc = new ServiceController(serviceName);
                Console.WriteLine($"Service '{serviceName}' status: {sc.Status}");

                // If running, stop it first
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    MessageBox.Show("Restarting Worker Service...");
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }

                // Start the service
                Console.WriteLine("Starting service...");
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                MessageBox.Show("Worker Service Started Successfully...");
            }
            catch (InvalidOperationException ex)
            {
                string message = $"Service '{serviceName}' not found or cannot be controlled: {ex.Message}";
                if (ex.Message.Contains("InteractiveLauncher service on computer"))
                {
                    message = message + "\n Please re-run the program as an admin";
                }
                MessageBox.Show(message);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error controlling service: {ex.Message}");
            }
        }

        // ----- GUI Logger ----
        private async void StartListening()
        {
            try
            {
                _listener = new TcpListener(IPAddress.Loopback, _port); // localhost only
                _listener.Start();
                _listening = true;

                while (_listening)
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync();
                    _ = HandleClientAsync(client); // fire-and-forget
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting listener: {ex.Message}");
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            using (NetworkStream stream = client.GetStream())
            {
                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Dispatcher.Invoke(() =>
                    {
                        WriteToLogs(message);
                        LogsTextBox.ScrollToEnd(); // keep latest log visible
                    });
                }
            }
        }

        private void WriteToLogs(string log)
        {
            if (!string.IsNullOrEmpty(log))
            {
                // Trim trailing newlines
                log = log.TrimEnd('\r', '\n');

                // Append to TextBox
                LogsTextBox.AppendText(log + Environment.NewLine);
                LogsTextBox.ScrollToEnd();

                try
                {
                    // Append to log file
                    File.AppendAllText(_logFilePath, log + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error writing to log file: " + ex.Message);
                }
            }
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            _listening = false;
            _listener?.Stop();
        }
        // --------------------
        private async Task SendCommandAsync(string exePath, string cmdSequence)
        {
            string args = $"/c \"{cmdSequence}\"";

            var req = new
            {
                exe = exePath,
                args = args,
                workDir = Path.GetDirectoryName(exePath),
                sessionId = (int?)null,
                timeoutSec = 30,
                userName = (string)null,
                loadUserProfile = true,
                isSilent = IsSilentCheckbox.IsChecked,
            };

            string json = JsonConvert.SerializeObject(req);

            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync("127.0.0.1", 49321);

                    using (var ns = client.GetStream())
                    using (var writer = new StreamWriter(ns, new UTF8Encoding(false)) { AutoFlush = true })
                    using (var reader = new StreamReader(ns, new UTF8Encoding(false)))
                    {
                        await writer.WriteLineAsync(json);
                        string response = await reader.ReadLineAsync();
                        WriteToLogs("Response: " + response);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex);
            }
        }
        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            string program = _txtFilePath;
            string args = ArgsTextbox.Text;

            if(string.IsNullOrEmpty(_txtFilePath))
            {
                MessageBox.Show($"No EXE was selected");
            }
            else
            {
                // MessageBox.Show($"Launching {program} with args {args}");
                WriteToLogs($"Launching {program} with args {args}");
                _ = SendCommandAsync(program, args);
            }
        }

        private void SetTargetEXE(object sender, RoutedEventArgs e)
        {
            string txtFilePath;
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                _txtFilePath = openFileDialog.FileName;
            }
        }

        private void IsSilentCheckbox_Checked(object sender, RoutedEventArgs e)
        {

        }
    }
}
