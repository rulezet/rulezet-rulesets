rule EditKeyLogReadMe_RID2D10 : DEMO SUSP {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe_RID2D10.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:15:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
      $s1 = "WinEggDrop.DLL" fullword ascii
      $s2 = "nc.exe" fullword ascii
      $s3 = "KeyLog.exe" fullword ascii
      $s4 = "EditKeyLog.exe" fullword ascii
      $s5 = "wineggdrop" fullword ascii
   condition: 
      3 of them
}