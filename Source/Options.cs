using System;
using CommandLine;
using CommandLine.Text;

namespace totalviruschecker
{
    /// <summary>
    /// Internal class used for the command line parsing
    /// </summary>
    internal class Options : CommandLineOptionsBase
    {
        [Option("f", "file", Required = false, DefaultValue = "", HelpText = "File containing hashes")]
        public string File { get; set; }

        [Option("t", "type", Required = true, DefaultValue = "md5", HelpText = "Valid values are md5 or sha1")]
        public string Type { get; set; }

        [Option("h", "hash", Required = false, DefaultValue = "", HelpText = "A single MD5 hash")]
        public string Hash { get; set; }

        [Option("d", "delimiter", Required = false, DefaultValue = ",", HelpText = "The delimiter used for the export. Defaults to \",\"")]
        public string Delimiter { get; set; }

        [Option("o", "output", Required = true, DefaultValue = "", HelpText = "Output directory")]
        public string Output { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            var help = new HelpText
            {
                Copyright = new CopyrightInfo("woanware", 2013),
                AdditionalNewLineAfterOption = false,
                AddDashesToOption = true
            };

            this.HandleParsingErrorsInHelp(help);

            help.AddPreOptionsLine("Usage: totalviruschecker -t hash -h \"MD5\" -d \"\\t\" -o \"C:\\output.csv\"");
            help.AddPreOptionsLine("       totalviruschecker -t file -f \"hashes.txt\"");
            help.AddOptions(this);

            return help;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="help"></param>
        private void HandleParsingErrorsInHelp(HelpText help)
        {
            if (this.LastPostParsingState.Errors.Count > 0)
            {
                var errors = help.RenderParsingErrorsText(this, 2); // indent with two spaces
                if (!string.IsNullOrEmpty(errors))
                {
                    help.AddPreOptionsLine(string.Concat(Environment.NewLine, "ERROR(S):"));
                    help.AddPreOptionsLine(errors);
                }
            }
        }
    }
}
