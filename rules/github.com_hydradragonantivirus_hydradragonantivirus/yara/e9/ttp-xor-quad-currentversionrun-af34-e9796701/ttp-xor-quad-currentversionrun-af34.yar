rule TTP_XOR_QUAD_CurrentVersionRun_af34 {
  strings:
    $key_af34 = { fc 5b [2] d8 55 [2] f3 79 [2] dd 5b [2] c9 40 [2] c6 5a [2] d8 47 [2] da 46 [2] c1 40 [2] dd 47 [2] c1 68 }

  condition:
    any of them
}