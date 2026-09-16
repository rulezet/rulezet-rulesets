rule TTP_XOR_QUAD_CurrentVersionRun_af12 {
  strings:
    $key_af12 = { fc 7d [2] d8 73 [2] f3 5f [2] dd 7d [2] c9 66 [2] c6 7c [2] d8 61 [2] da 60 [2] c1 66 [2] dd 61 [2] c1 4e }

  condition:
    any of them
}