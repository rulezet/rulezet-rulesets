rule TTP_XOR_QUAD_CurrentVersionRun_af4e {
  strings:
    $key_af4e = { fc 21 [2] d8 2f [2] f3 03 [2] dd 21 [2] c9 3a [2] c6 20 [2] d8 3d [2] da 3c [2] c1 3a [2] dd 3d [2] c1 12 }

  condition:
    any of them
}