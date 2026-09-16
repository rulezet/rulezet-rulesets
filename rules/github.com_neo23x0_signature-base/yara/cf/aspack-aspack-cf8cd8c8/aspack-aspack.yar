rule ASPack_ASPACK {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
      id = "ca9a25f9-a94b-5e10-b935-c6e2d38d999c"
   strings:
      $s0 = "ASPACK.EXE" fullword wide
      $s5 = "CLOSEDFOLDER" fullword wide
      $s10 = "ASPack compressor" fullword wide
   condition:
      all of them
}