rule EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
      id = "95594756-1872-5d86-877f-0977bd3c067b"
   strings:
      $x1 = "[+] Connected to target %s:%d" fullword ascii
      $x2 = "[-] build_exploit_run_x64():" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}