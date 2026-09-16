rule Hacktools_CN_Panda_tasksvr {
   meta:
      description = "Disclosed hacktool set - file tasksvr.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
      id = "5c85b382-551a-5e9e-9af8-d106cbe26f74"
   strings:
      $s2 = "Consys21.dll" fullword ascii
      $s4 = "360EntCall.exe" fullword wide
      $s15 = "Beijing1" fullword ascii
   condition:
      all of them
}