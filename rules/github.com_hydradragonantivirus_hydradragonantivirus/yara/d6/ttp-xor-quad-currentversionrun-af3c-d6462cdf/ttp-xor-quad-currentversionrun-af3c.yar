rule TTP_XOR_QUAD_CurrentVersionRun_af3c {
  strings:
    $key_af3c = { fc 53 [2] d8 5d [2] f3 71 [2] dd 53 [2] c9 48 [2] c6 52 [2] d8 4f [2] da 4e [2] c1 48 [2] dd 4f [2] c1 60 }

  condition:
    any of them
}