rule aspbackdoor_ipclear {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
      id = "71ebecea-721f-5c5d-9997-6a57f070d91c"
   strings:
      $s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
      $s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
      $s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
      $s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
      $s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
   condition:
      all of them
}