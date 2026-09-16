rule SUSP_Reversed_Hacktool_Author_RID3261 : DEMO FILE SUSP {
   meta:
      description = "Detects a suspicious path traversal into a Windows folder"
      author = "Florian Roth"
      reference = "https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/"
      date = "2020-06-10 14:02:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "iwiklitneg" fullword ascii wide
      $x2 = " eetbus@ " ascii wide
   condition: 
      filesize < 4000KB and 1 of them
}