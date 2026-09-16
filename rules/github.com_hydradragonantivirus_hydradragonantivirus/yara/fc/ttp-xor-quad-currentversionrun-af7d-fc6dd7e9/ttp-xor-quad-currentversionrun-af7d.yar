rule TTP_XOR_QUAD_CurrentVersionRun_af7d {
  strings:
    $key_af7d = { fc 12 [2] d8 1c [2] f3 30 [2] dd 12 [2] c9 09 [2] c6 13 [2] d8 0e [2] da 0f [2] c1 09 [2] dd 0e [2] c1 21 }

  condition:
    any of them
}