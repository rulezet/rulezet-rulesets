rule CN_Hacktool_S_EXE_Portscanner {
   meta:
      description = "Detects a chinese Portscanner named s.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 70
      date = "12.10.2014"
      id = "d6b35d4f-7e25-50dd-bef2-08f7033312e8"
   strings:
      $s0 = "\\Result.txt" ascii
      $s1 = "By:ZT QQ:376789051" fullword ascii
      $s2 = "(http://www.eyuyan.com)" fullword wide
   condition:
      all of them
}