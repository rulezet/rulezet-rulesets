rule Hacktools_CN_Burst_pass {
   meta:
      description = "Disclosed hacktool set - file pass.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "55a05cf93dbd274355d798534be471dff26803f9"
      id = "d8f6784f-80c8-51e2-9d86-40022cd8705d"
   strings:
      $s0 = "123456.com" fullword ascii
      $s1 = "123123.com" fullword ascii
      $s2 = "360.com" fullword ascii
      $s3 = "123.com" fullword ascii
      $s4 = "juso.com" fullword ascii
      $s5 = "sina.com" fullword ascii
      $s7 = "changeme" fullword ascii
      $s8 = "master" fullword ascii
      $s9 = "google.com" fullword ascii
      $s10 = "chinanet" fullword ascii
      $s12 = "lionking" fullword ascii
   condition:
      all of them
}