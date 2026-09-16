rule TTP_XOR_QUAD_CurrentVersionRun_b41c {
  strings:
    $key_b41c = { e7 73 [2] c3 7d [2] e8 51 [2] c6 73 [2] d2 68 [2] dd 72 [2] c3 6f [2] c1 6e [2] da 68 [2] c6 6f [2] da 40 }

  condition:
    any of them
}