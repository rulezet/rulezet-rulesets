rule CN_Hacktool_ScanPort_Portscanner {
   meta:
      description = "Detects a chinese Portscanner named ScanPort"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 70
      date = "12.10.2014"
      id = "a708283e-339c-599f-9321-3b063d0076a9"
   strings:
      $s0 = "LScanPort" fullword wide
      $s1 = "LScanPort Microsoft" fullword wide
      $s2 = "www.yupsoft.com" fullword wide
   condition:
      all of them
}