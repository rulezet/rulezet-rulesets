rule EquationGroup_store_linux_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"
      id = "b88be148-5308-583a-b41e-2bea9b837e2a"
   strings:
      $s1 = "[-] Failed to map file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "[!] Name has size of 0!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}