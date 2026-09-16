rule EquationGroup_Toolset_Apr17_GangsterThief_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "50b269bda5fedcf5a62ee0514c4b14d48d53dd18ac3075dcc80b52d0c2783e06"
      id = "9127f280-135e-5f83-9587-eab3ad84ad69"
   strings:
      $s1 = "\\\\.\\%s:" fullword wide
      $s4 = "raw_open CreateFile error" fullword ascii
      $s5 = "-PATHDELETED-" ascii
      $s6 = "(deleted)" fullword wide
      $s8 = "NULLFILENAME" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}