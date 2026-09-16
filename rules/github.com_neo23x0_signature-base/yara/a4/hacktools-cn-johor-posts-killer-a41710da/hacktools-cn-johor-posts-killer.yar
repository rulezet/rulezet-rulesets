rule Hacktools_CN_JoHor_Posts_Killer {
   meta:
      description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
      id = "68bba78e-f3a0-5eaa-9c63-e5f23a76b328"
   strings:
      $s0 = "Multithreading Posts_Send Killer" fullword ascii
      $s3 = "GET [Access Point] HTTP/1.1" fullword ascii
      $s6 = "The program's need files was not exist!" fullword ascii
      $s7 = "JoHor_Posts_Killer" fullword wide
      $s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
      $s10 = "  ( /s ) :" fullword ascii
      $s11 = "forms.vbp" fullword ascii
      $s12 = "forms.vcp" fullword ascii
      $s13 = "Software\\FlySky\\E\\Install" fullword ascii
   condition:
      5 of them
}