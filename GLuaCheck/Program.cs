using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace GLuaCheck
{
    class Program
    {
        public class iScannableItem
        {
            public Regex DetectionRegex { get; set; }

            public string Name { get; set; }

            public string Description { get; set; }

            public int Severity { get; set; }

            public override string ToString()
            {
                return Name;
            }

        }
        public class iScannableItemFound
        { 
            public string Name { get; set; }

            public string Description { get; set; }

            public string Snippet { get; set; }
            public int Severity { get; set; }

            public string Filename { get; set; }

            public int Line { get; set; }

            public override string ToString()
            {
                return Name+":"+Severity+"|"+Description+"|"+Filename+":"+Line;
            }

        }

        static void CreateConfigurationFiles()
        {

            List<iScannableItem> Items = new List<iScannableItem>();

            /*
             * Default iScannableItem list
             */
            #region Default ScannableItems

            Items.Add(new iScannableItem()
            {
                Name = "_G Access",
                DetectionRegex = new Regex("_G"),
                Description = "Can be used to get any global variable, often used to hide what function is getting called.",
                Severity = 3
            });

            Items.Add(new iScannableItem()
            {
                Name = "Lua execution",
                DetectionRegex = new Regex("CompileString"),
                Description = "Dynamic code execution",
                Severity = 3
            });
            Items.Add(new iScannableItem()
            {
                Name = "Lua execution",
                DetectionRegex = new Regex("RunString"),
                Description = "Dynamic code execution",
                Severity = 3
            });

            Items.Add(new iScannableItem()
            {
                Name = "Obfuscated Lua",
                DetectionRegex = new Regex("/0[xX][0-9a-fA-F]+/"),
                Description = "Can be used to hide a DRM or an Backdoor.",
                Severity = 3
            });
            Items.Add(new iScannableItem()
            {
                Name = "Obfuscated Lua",
                DetectionRegex = new Regex("/\\[0-9]+\\[0-9]+/"),
                Description = "Can be used to hide a DRM or an Backdoor.",
                Severity = 3
            });
            Items.Add(new iScannableItem()
            {
                Name = "Obfuscated Lua",
                DetectionRegex = new Regex("/\\[xX] [0-9a-fA-F] [0-9a-fA-F]/"),
                Description = "Used to hide a DRM or backdoor.",
                Severity = 3
            });
                         
            Items.Add(new iScannableItem()
            {
                Name = "External Networking",
                DetectionRegex = new Regex("^(?: http(s) ?:\\/\\/)?[\\w.-]+(?:\\.[\\w\\.-]+)+[\\w\\-\\._~:/?#[\\]@!\\$&'\\(\\)\\*\\+,;=.]+$"),
                Description = "Used to get info from external source, like latest version or possibly a backdoor to run code.",
                Severity = 2
            });

            Items.Add(new iScannableItem()
            {
                Name = "External Networking",
                DetectionRegex = new Regex("http.Fetch"),
                Description = "Used to get info from external source, like latest version or possibly a backdoor to run code.",
                Severity = 2
            });

            Items.Add(new iScannableItem()
            {
                Name = "External Networking",
                DetectionRegex = new Regex("http.Post"),
                Description = "Used to get info from external source, like latest version or possibly a backdoor to run code.",
                Severity = 2
            });

            Items.Add(new iScannableItem()
            {
                Name = "Console Command",
                DetectionRegex = new Regex("game.ConsoleCommand"),
                Description = "Runs console command on the server. Can execute and do almost anything.",
                Severity = 2
            });

            Items.Add(new iScannableItem()
            {
                Name = "Console Command",
                DetectionRegex = new Regex("RunConsoleCommand"),
                Description = "Runs console command on the server. Can execute and do almost anything.",
                Severity = 2
            });


            Items.Add(new iScannableItem()
            {
                Name = "Console Command",
                DetectionRegex = new Regex(":ConCommand"),
                Description = "	Runs console command on a client. Can be used by backdoors to make it look like admins are doing things.",
                Severity = 2
            });


            Items.Add(new iScannableItem()
            {
                Name = "setmetatable",
                DetectionRegex = new Regex("setmetatable"),
                Description = "Setting metatable.",
                Severity = 1
            });

            Items.Add(new iScannableItem()
            {
                Name = "hostip",
                DetectionRegex = new Regex("IP Tracking"),
                Description = "Allows getting IP address of the server. Often used for statistics or tracking backdoored servers.",
                Severity = 1
            });
            #endregion

            File.WriteAllText("./glc_checks.json", JsonConvert.SerializeObject(Items, Formatting.Indented));
        }

        static List<iScannableItem> LoadConfiguration()
        {
            if(!File.Exists("./glc_checks.json"))
            {
                CreateConfigurationFiles();
            }

            return JsonConvert.DeserializeObject<List<iScannableItem>>(File.ReadAllText("./glc_checks.json"));

        }


        static void Main(string[] args)
        {
            string[] indexedFiles;
            string path = "";
            string logtype = "txt";

            List<iScannableItem> scannableItems = LoadConfiguration();
            List<iScannableItemFound> foundItems;



            if (args.Count() >= 1)
            {
                path = args[0].ToString();
            }

            try
            {
                logtype = args[1].ToString();
            } catch(Exception) { }

            indexedFiles = IndexDir(path);
            foundItems = ScanFiles(indexedFiles, scannableItems);

            WriteLogFiles(foundItems, logtype);

            foreach (var item in foundItems)
            {
                Console.WriteLine(item);
            }

        }

        static string[] IndexDir(string path,string searchFor = "*.lua")
        { 
            try
            {
                return Directory.GetFiles(@path, searchFor, SearchOption.AllDirectories);
            } catch(Exception) {
                return new string[] { };
            }
        }

        static List<iScannableItemFound> ScanFiles(string[] files, List<iScannableItem> scan)
        {
            char[] trimChars = {' '};
            List<iScannableItemFound> foundItems = new List<iScannableItemFound>();
            foreach (var file in files)
            { 
                string[] Lines = File.ReadAllLines(file);

                foreach (var scanItem in scan)
                {
                    int Line = 0;
                    foreach (var LineScan in Lines)
                    {
                        Line++;
                        if(scanItem.DetectionRegex.IsMatch(LineScan))
                        {
                            string snip = ">>>"+LineScan.Trim(trimChars)+"<<<";
                            if (Line > 1)
                            {
                                snip = Lines[Line - 2].Trim(trimChars) + "\n" + snip;
                            }
                            if (Line < Lines.Count() -1)
                            {
                                snip = snip + "\n" + Lines[Line + 1].Trim(trimChars);
                            }

                            foundItems.Add(new iScannableItemFound()
                            { 
                                Name = scanItem.Name,
                                Filename = file,
                                Line = Line,
                                Snippet = snip,
                                Description = scanItem.Description,
                                Severity = scanItem.Severity
                            });
                        }
                    } 
                }
            }
            return foundItems;
        }

        static void WriteLogFiles(List<iScannableItemFound> itemFounds,string type)
        {
            string file = "./glc_logs.";

            List<string> data = new List<string>();
            foreach (var item in itemFounds)
            {
                data.Add(item.ToString());
            }

            switch (type)
            {
                case "json":
                    File.WriteAllText(file+"json", JsonConvert.SerializeObject(itemFounds, Formatting.Indented));
                    break;
                default: 
                    file += "txt";
                    File.WriteAllLines(file, data);
                    break;
            }
        }
    }
}
