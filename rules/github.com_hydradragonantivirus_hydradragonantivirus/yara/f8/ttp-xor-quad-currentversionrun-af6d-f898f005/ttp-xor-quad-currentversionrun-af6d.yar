rule TTP_XOR_QUAD_CurrentVersionRun_af6d {
  strings:
    $key_af6d = { fc 02 [2] d8 0c [2] f3 20 [2] dd 02 [2] c9 19 [2] c6 03 [2] d8 1e [2] da 1f [2] c1 19 [2] dd 1e [2] c1 31 }

  condition:
    any of them
}