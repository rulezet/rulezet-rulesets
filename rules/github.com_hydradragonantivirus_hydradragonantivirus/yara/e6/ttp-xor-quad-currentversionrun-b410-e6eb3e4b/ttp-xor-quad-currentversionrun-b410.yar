rule TTP_XOR_QUAD_CurrentVersionRun_b410 {
  strings:
    $key_b410 = { e7 7f [2] c3 71 [2] e8 5d [2] c6 7f [2] d2 64 [2] dd 7e [2] c3 63 [2] c1 62 [2] da 64 [2] c6 63 [2] da 4c }

  condition:
    any of them
}