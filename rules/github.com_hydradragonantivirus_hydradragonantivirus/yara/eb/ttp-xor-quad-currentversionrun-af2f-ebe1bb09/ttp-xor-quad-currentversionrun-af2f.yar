rule TTP_XOR_QUAD_CurrentVersionRun_af2f {
  strings:
    $key_af2f = { fc 40 [2] d8 4e [2] f3 62 [2] dd 40 [2] c9 5b [2] c6 41 [2] d8 5c [2] da 5d [2] c1 5b [2] dd 5c [2] c1 73 }

  condition:
    any of them
}