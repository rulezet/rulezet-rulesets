rule TTP_XOR_QUAD_CurrentVersionRun_b47d {
  strings:
    $key_b47d = { e7 12 [2] c3 1c [2] e8 30 [2] c6 12 [2] d2 09 [2] dd 13 [2] c3 0e [2] c1 0f [2] da 09 [2] c6 0e [2] da 21 }

  condition:
    any of them
}