rule aspbackdoor_asp4 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp4.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "faf991664fd82a8755feb65334e5130f791baa8c"
      id = "7718aa71-fc0f-505c-a035-b78ae0438653"
   strings:
      $s0 = "system.dll" fullword ascii
      $s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
      $s3 = "Public Function reboot(atype As Variant)" fullword ascii
      $s4 = "t& = ExitWindowsEx(1, atype)" ascii
      $s5 = "atype=request(\"atype\") " fullword ascii
      $s7 = "AceiveX dll" fullword ascii
      $s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
      $s10 = "sys.reboot(atype)" fullword ascii
   condition:
      all of them
}