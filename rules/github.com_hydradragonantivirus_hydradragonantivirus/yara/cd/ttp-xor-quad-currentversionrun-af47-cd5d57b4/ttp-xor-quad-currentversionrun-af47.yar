rule TTP_XOR_QUAD_CurrentVersionRun_af47 {
  strings:
    $key_af47 = { fc 28 [2] d8 26 [2] f3 0a [2] dd 28 [2] c9 33 [2] c6 29 [2] d8 34 [2] da 35 [2] c1 33 [2] dd 34 [2] c1 1b }

  condition:
    any of them
}