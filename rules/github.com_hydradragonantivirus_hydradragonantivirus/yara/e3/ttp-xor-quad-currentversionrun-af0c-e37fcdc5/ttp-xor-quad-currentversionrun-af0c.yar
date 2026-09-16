rule TTP_XOR_QUAD_CurrentVersionRun_af0c {
  strings:
    $key_af0c = { fc 63 [2] d8 6d [2] f3 41 [2] dd 63 [2] c9 78 [2] c6 62 [2] d8 7f [2] da 7e [2] c1 78 [2] dd 7f [2] c1 50 }

  condition:
    any of them
}