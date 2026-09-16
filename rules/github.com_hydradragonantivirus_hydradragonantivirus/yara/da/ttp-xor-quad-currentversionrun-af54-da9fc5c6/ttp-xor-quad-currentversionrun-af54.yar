rule TTP_XOR_QUAD_CurrentVersionRun_af54 {
  strings:
    $key_af54 = { fc 3b [2] d8 35 [2] f3 19 [2] dd 3b [2] c9 20 [2] c6 3a [2] d8 27 [2] da 26 [2] c1 20 [2] dd 27 [2] c1 08 }

  condition:
    any of them
}