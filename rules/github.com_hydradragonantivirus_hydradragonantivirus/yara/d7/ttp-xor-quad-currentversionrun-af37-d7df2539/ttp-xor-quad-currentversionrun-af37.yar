rule TTP_XOR_QUAD_CurrentVersionRun_af37 {
  strings:
    $key_af37 = { fc 58 [2] d8 56 [2] f3 7a [2] dd 58 [2] c9 43 [2] c6 59 [2] d8 44 [2] da 45 [2] c1 43 [2] dd 44 [2] c1 6b }

  condition:
    any of them
}