rule TTP_XOR_QUAD_CurrentVersionRun_af77 {
  strings:
    $key_af77 = { fc 18 [2] d8 16 [2] f3 3a [2] dd 18 [2] c9 03 [2] c6 19 [2] d8 04 [2] da 05 [2] c1 03 [2] dd 04 [2] c1 2b }

  condition:
    any of them
}