rule TTP_XOR_QUAD_CurrentVersionRun_af72 {
  strings:
    $key_af72 = { fc 1d [2] d8 13 [2] f3 3f [2] dd 1d [2] c9 06 [2] c6 1c [2] d8 01 [2] da 00 [2] c1 06 [2] dd 01 [2] c1 2e }

  condition:
    any of them
}