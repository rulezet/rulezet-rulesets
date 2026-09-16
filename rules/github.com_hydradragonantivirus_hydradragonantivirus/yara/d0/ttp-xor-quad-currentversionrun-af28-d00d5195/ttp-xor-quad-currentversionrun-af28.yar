rule TTP_XOR_QUAD_CurrentVersionRun_af28 {
  strings:
    $key_af28 = { fc 47 [2] d8 49 [2] f3 65 [2] dd 47 [2] c9 5c [2] c6 46 [2] d8 5b [2] da 5a [2] c1 5c [2] dd 5b [2] c1 74 }

  condition:
    any of them
}