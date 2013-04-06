using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using CommandLine;
using VirusTotalNET;
using woanware;

namespace totalviruschecker
{
    class Program
    {
        #region Member Variables
        private static Settings _settings;
        private static ManualResetEvent _reset;
        private static Options _options;
        #endregion

        /// <summary>
        /// Entry point
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                AssemblyName assemblyName = assembly.GetName();

                Console.WriteLine(Environment.NewLine + "virustotalchecker v" + assemblyName.Version.ToString(3) + Environment.NewLine);

                _options = new Options();
                if (CommandLineParser.Default.ParseArguments(args, _options) == false)
                {
                    return;
                }

                _settings = new Settings();
                string ret = _settings.Load();
                if (ret.Length > 0)
                {
                    Console.WriteLine(ret);
                    return;
                }

                if (_settings.ApiKey.Length == 0)
                {
                    Console.WriteLine("The API key has not been set in the settings file");
                    return;
                }

                if (_options.File.Length == 0 & _options.Hash.Length == 0)
                {
                    Console.WriteLine("Either the file or hash parameter must be set");
                    return;
                }

                if (_options.File.Length > 0 & _options.Hash.Length > 0)
                {
                    Console.WriteLine("Both the file and hash parameters have been set. Choose one or the other");
                    return;
                }

                CacheChecker cacheChecker = new CacheChecker(_settings.ApiKey, Misc.GetApplicationDirectory());
                cacheChecker.HashChecked += OnCacheChecker_HashChecked;
                cacheChecker.Complete += OnCacheChecker_Complete;
                cacheChecker.Error += OnCacheChecker_Error;

                if (_options.Output.Length > 0)
                {
                    if (File.Exists(_options.Output) == false)
                    {
                        IO.WriteTextToFile(string.Format("{1}{0}{2}{0}{3}" + Environment.NewLine, GetDelimiter(), "MD5", "Positives", "Total"), System.IO.Path.Combine(_options.Output, "virustotalchecker.csv"), false);
                    }
                }

                if (_options.File.Length > 0)
                {
                    List<string> hashes = File.ReadAllLines(_options.File).Cast<string>().ToList();
                    cacheChecker.Start(hashes);
                }
                else
                {
                    cacheChecker.Start(_options.Hash);
                }

                _reset = new ManualResetEvent(false);
                _reset.WaitOne();
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private static char GetDelimiter()
        {
            switch (_options.Delimiter)
            {
                case "'\\t'":
                    return '\t';
                case "\\t":
                    return '\t';
                default:
                    return char.Parse(_options.Delimiter);
            }
        }

        #region Cache Checker Event Handlers
        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        private static void OnCacheChecker_Error(string message)
        {
            Console.WriteLine(message);
        }

        /// <summary>
        /// 
        /// </summary>
        private static void OnCacheChecker_Complete()
        {
            Console.WriteLine("Complete");
            _reset.Set();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="report"></param>
        private static void OnCacheChecker_HashChecked(VirusTotalNET.Objects.Report report)
        {
            if (report.Total == 0)
            {
                IO.WriteTextToFile(report.Md5 + Environment.NewLine, System.IO.Path.Combine(_options.Output, "Failed.csv"), true);
                Console.WriteLine("Failed: " + report.Md5);
            }
            else
            {
                Console.WriteLine(report.Md5 + ": " + report.Positives + "/" + report.Total);
                if (_options.Output.Length > 0)
                {
                    IO.WriteTextToFile(string.Format("{1}{0}{2}{0}{3}" + Environment.NewLine, GetDelimiter(), report.Md5, report.Positives, report.Total), System.IO.Path.Combine(_options.Output, "virustotalchecker.csv"), true);
                }
            }
        }
        #endregion
    }
}
