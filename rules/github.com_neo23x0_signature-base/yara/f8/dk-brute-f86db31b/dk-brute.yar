rule DK_Brute {
   meta:
      description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "22.11.14"
      score = 70
      reference = "http://goo.gl/xiIphp"
      hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
      id = "c9ea0dcf-10f3-5161-aebc-2db04c24b0a5"
   strings:
      $s6 = "get_CrackedCredentials" fullword ascii
      $s13 = "Same port used for two different protocols:" fullword wide
      $s18 = "coded by fLaSh" fullword ascii
      $s19 = "get_grbToolsScaningCracking" fullword ascii
   condition:
      all of them
}