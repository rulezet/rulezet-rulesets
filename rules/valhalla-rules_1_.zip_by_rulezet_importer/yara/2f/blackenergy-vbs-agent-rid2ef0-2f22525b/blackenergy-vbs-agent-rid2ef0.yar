rule BlackEnergy_VBS_Agent_RID2EF0 : APT DEMO SCRIPT blackenergy {
   meta:
      description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs"
      author = "Florian Roth"
      reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
      date = "2016-01-03 11:35:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
      $s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
      $s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii
   condition: 
      filesize < 1KB and 2 of them
}