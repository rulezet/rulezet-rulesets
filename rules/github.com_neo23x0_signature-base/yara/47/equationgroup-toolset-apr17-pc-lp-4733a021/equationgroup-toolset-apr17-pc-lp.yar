rule EquationGroup_Toolset_Apr17_PC_LP {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"
      id = "c3f8f0f9-80ab-5d8e-be42-59b90dc291cb"
   strings:
      $s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
      $s2 = "Format: <command> <target port> [lp port]" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}