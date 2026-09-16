rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_RID3323 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file h4ntu shell [powered by tsoi].txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<title>h4ntu shell" 
      $x2 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");" 
   condition: 
      filesize < 100KB and 1 of them
}