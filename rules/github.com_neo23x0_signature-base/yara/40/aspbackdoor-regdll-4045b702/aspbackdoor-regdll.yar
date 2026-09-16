rule aspbackdoor_regdll {
   meta:
      description = "Disclosed hacktool set (old stuff) - file regdll.asp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
      id = "37096c50-68d0-5412-847a-022062a5ff2a"
   strings:
      $s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
      $s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
      $s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
      $s5 = "Public Property Get oFS()" fullword ascii
   condition:
      all of them
}