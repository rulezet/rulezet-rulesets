rule Hacktools_CN_Panda_445 {
   meta:
      description = "Disclosed hacktool set - file 445.rar"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
      id = "02075631-49cc-5b97-ad8e-92d734a26d34"
   strings:
      $s0 = "for /f %%i in (ips.txt) do (start cmd.bat %%i)" fullword ascii
      $s1 = "445\\nc.exe" fullword ascii
      $s2 = "445\\s.exe" fullword ascii
      $s3 = "cs.exe %1" fullword ascii
      $s4 = "445\\cs.exe" fullword ascii
      $s5 = "445\\ip.txt" fullword ascii
      $s6 = "445\\cmd.bat" fullword ascii
      $s9 = "@echo off" fullword ascii
   condition:
      all of them
}