rule TTP_XOR_QUAD_CurrentVersionRun_af61 {
  strings:
    $key_af61 = { fc 0e [2] d8 00 [2] f3 2c [2] dd 0e [2] c9 15 [2] c6 0f [2] d8 12 [2] da 13 [2] c1 15 [2] dd 12 [2] c1 3d }

  condition:
    any of them
}