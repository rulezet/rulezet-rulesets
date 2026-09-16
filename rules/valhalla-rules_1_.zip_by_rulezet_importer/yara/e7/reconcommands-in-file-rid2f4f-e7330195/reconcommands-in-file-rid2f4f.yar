rule ReconCommands_in_File_RID2F4F : DEMO FILE SUSP T1007 T1033 T1057 T1082 {
   meta:
      description = "Detects various recon commands in a single file"
      author = "Florian Roth"
      reference = "https://twitter.com/haroonmeer/status/939099379834658817"
      date = "2017-12-11 11:51:41"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP, T1007, T1033, T1057, T1082"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "tasklist" 
      $ = "net time" 
      $ = "systeminfo" 
      $ = "whoami" 
      $ = "nbtstat" 
      $ = "net start" 
      $ = "qprocess" 
      $ = "nslookup" 
   condition: 
      filesize < 5KB and 4 of them
}