rule TTP_XOR_QUAD_CurrentVersionRun_afff {
  strings:
    $key_afff = { fc 90 [2] d8 9e [2] f3 b2 [2] dd 90 [2] c9 8b [2] c6 91 [2] d8 8c [2] da 8d [2] c1 8b [2] dd 8c [2] c1 a3 }

  condition:
    any of them
}