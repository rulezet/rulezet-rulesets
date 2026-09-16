rule Webshell_aspbackdoor_asp4_RID3106 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file asp4.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:04:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
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