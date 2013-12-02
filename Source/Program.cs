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
        private static long _count = 0;
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

                string databasePath = string.Empty;
                if (_options.Database.Length > 0)
                {
                    databasePath = _options.Database;
                }
                else
                {
                    databasePath = Misc.GetApplicationDirectory();
                }

                if (_options.Import.Length > 0)
                {
                    PerformImport(databasePath);
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

                Global.Mode mode = Global.Mode.Cache;
                switch (_options.Mode.ToLower())
                {
                    case "c":
                        mode = Global.Mode.Cache;
                        break;
                    case "d":
                        mode = Global.Mode.Database;
                        break;
                    case "l":
                        mode = Global.Mode.Live;
                        break;
                    default:
                        Console.WriteLine("Invalid mode e.g. c = caching, d = database only, l = live");
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

                if (_options.File.Trim().Length > 0)
                {
                    if (_options.Output.Length == 0)
                    {
                        Console.WriteLine("The output parameter must be set");
                        return;
                    }

                    if (File.Exists(_options.File) == false)
                    {
                        Console.WriteLine("The input file does not exist");
                        return;
                    }
                }

                CacheChecker cacheChecker = new CacheChecker(_settings.ApiKey, databasePath);
                cacheChecker.HashChecked += OnCacheChecker_HashChecked;
                cacheChecker.Complete += OnCacheChecker_Complete;
                cacheChecker.Error += OnCacheChecker_Error;

                // Output the CSV file header
                IO.WriteTextToFile(string.Format("{1}{0}{2}{0}{3}{0}{4}{0}{5}" + Environment.NewLine, GetDelimiter(), "MD5", "SHA256", "Positive", "Total", "DETECTED"), System.IO.Path.Combine(_options.Output, "virustotalchecker.csv"), false);



                if (_options.File.Length > 0)
                {
                    //List<string> hashes = File.ReadAllLines(_options.File).Cast<string>().ToList();
                    //cacheChecker.Start(hashes, _options.Live);
                    cacheChecker.StartFile(_options.File, mode);
                }
                else
                {
                    cacheChecker.Start(_options.Hash, mode);
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="databasePath"></param>
        private static void PerformImport(string databasePath)
        {
            CacheChecker cacheChecker = new CacheChecker(string.Empty, databasePath);
            cacheChecker.ImportComplete += OnCacheChecker_ImportComplete;
            cacheChecker.Error += OnCacheChecker_Error;

            cacheChecker.Import(_options.Import);

            _reset = new ManualResetEvent(false);
            _reset.WaitOne();
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
        private static void OnCacheChecker_ImportComplete()
        {
            Console.WriteLine("Import complete");
            _reset.Set();
        }

        /// <summary>
        /// 
        /// </summary>
        private static void OnCacheChecker_Complete(string message)
        {
            Console.WriteLine(string.Empty);
            Console.WriteLine("Number of checked hashes: " + _count);
            Console.WriteLine("Duration: " + message);
            Console.WriteLine("Complete");
            _reset.Set();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash"></param>
        private static void OnCacheChecker_HashChecked(Hash hash)
        {
            _count++;

            if (hash.Total == 0)
            {
                if (_options.Output.Length > 0)
                {
                    IO.WriteTextToFile(string.Format("{0}{1}{2}", hash.Md5, GetDelimiter(), "Not in VT data") + Environment.NewLine, System.IO.Path.Combine(_options.Output, "Failed.csv"), true);
                }
                
                Console.WriteLine(string.Format("{0}: Not in VT data", hash.Md5));
            }
            else
            {
                if (hash.Scans.Length > 0)
                {
                    Console.WriteLine(hash.Md5 + ": " + hash.Positive + "/" + hash.Total + " (" + hash.Scans + ")");
                }
                else
                {
                    Console.WriteLine(hash.Md5 + ": " + hash.Positive + "/" + hash.Total);
                }

                if (_options.Output.Length > 0)
                {
                    IO.WriteTextToFile(string.Format("{1}{0}{2}{0}{3}{0}{4}{0}{5}" + Environment.NewLine, GetDelimiter(), hash.Md5, hash.Sha256, hash.Positive, hash.Total, hash.Scans), System.IO.Path.Combine(_options.Output, "virustotalchecker.csv"), true);
                }
            }
            
        }
        #endregion
    }
}
