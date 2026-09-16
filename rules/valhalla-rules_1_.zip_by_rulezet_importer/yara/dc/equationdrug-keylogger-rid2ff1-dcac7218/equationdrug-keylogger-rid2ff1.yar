rule EquationDrug_Keylogger_RID2FF1 : APT DEMO T1056_001 {
   meta:
      description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 12:18:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, T1056_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" wide
      $s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
      $s3 = "\\DosDevices\\Gk" wide
      $s5 = "\\Device\\Gk0" wide
   condition: 
      all of them
}