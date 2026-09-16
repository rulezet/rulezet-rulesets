rule TTP_XOR_QUAD_CurrentVersionRun_af5c {
  strings:
    $key_af5c = { fc 33 [2] d8 3d [2] f3 11 [2] dd 33 [2] c9 28 [2] c6 32 [2] d8 2f [2] da 2e [2] c1 28 [2] dd 2f [2] c1 00 }

  condition:
    any of them
}