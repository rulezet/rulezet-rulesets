rule TTP_XOR_QUAD_CurrentVersionRun_af48 {
  strings:
    $key_af48 = { fc 27 [2] d8 29 [2] f3 05 [2] dd 27 [2] c9 3c [2] c6 26 [2] d8 3b [2] da 3a [2] c1 3c [2] dd 3b [2] c1 14 }

  condition:
    any of them
}