rule TTP_XOR_QUAD_CurrentVersionRun_af19 {
  strings:
    $key_af19 = { fc 76 [2] d8 78 [2] f3 54 [2] dd 76 [2] c9 6d [2] c6 77 [2] d8 6a [2] da 6b [2] c1 6d [2] dd 6a [2] c1 45 }

  condition:
    any of them
}