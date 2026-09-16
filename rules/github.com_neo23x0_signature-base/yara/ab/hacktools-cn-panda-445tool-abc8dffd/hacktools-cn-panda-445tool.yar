rule Hacktools_CN_Panda_445TOOL {
   meta:
      description = "Disclosed hacktool set - file 445TOOL.rar"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "92050ba43029f914696289598cf3b18e34457a11"
      id = "02075631-49cc-5b97-ad8e-92d734a26d34"
   strings:
      $s0 = "scan.bat" fullword ascii
      $s1 = "Http.exe" fullword ascii
      $s2 = "GOGOGO.bat" fullword ascii
      $s3 = "ip.txt" fullword ascii
   condition:
      all of them
}