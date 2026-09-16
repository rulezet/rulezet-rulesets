rule aspbackdoor_ipclear_RID2ED9 : DEMO SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 11:32:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
      $s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
      $s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
      $s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
      $s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
   condition: 
      all of them
}