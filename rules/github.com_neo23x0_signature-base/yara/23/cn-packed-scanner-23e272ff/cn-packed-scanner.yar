rule CN_Packed_Scanner {
   meta:
      description = "Suspiciously packed executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
      score = 40
      date = "06.10.2014"
      id = "a11c4ee6-7244-5601-af26-a45f9fdc8e1b"
   strings:
      $s1 = "kernel32.dll" fullword ascii
      $s2 = "CRTDLL.DLL" fullword ascii
      $s3 = "__GetMainArgs" fullword ascii
      $s4 = "WS2_32.DLL" fullword ascii
   condition:
      all of them and filesize < 180KB and filesize > 70KB
}