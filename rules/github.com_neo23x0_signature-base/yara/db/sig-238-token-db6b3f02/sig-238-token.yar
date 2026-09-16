rule sig_238_token {
   meta:
      description = "Disclosed hacktool set (old stuff) - file token.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
      id = "9d0ac24b-2078-5455-8d9e-a642c71f7b2d"
   strings:
      $s0 = "Logon.exe" fullword ascii
      $s1 = "Domain And User:" fullword ascii
      $s2 = "PID=Get Addr$(): One" fullword ascii
      $s3 = "Process " fullword ascii
      $s4 = "psapi.dllK" fullword ascii
   condition:
      all of them
}