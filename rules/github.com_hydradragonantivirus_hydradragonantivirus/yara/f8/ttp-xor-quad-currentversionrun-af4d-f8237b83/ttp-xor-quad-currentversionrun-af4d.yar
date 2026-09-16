rule TTP_XOR_QUAD_CurrentVersionRun_af4d {
  strings:
    $key_af4d = { fc 22 [2] d8 2c [2] f3 00 [2] dd 22 [2] c9 39 [2] c6 23 [2] d8 3e [2] da 3f [2] c1 39 [2] dd 3e [2] c1 11 }

  condition:
    any of them
}