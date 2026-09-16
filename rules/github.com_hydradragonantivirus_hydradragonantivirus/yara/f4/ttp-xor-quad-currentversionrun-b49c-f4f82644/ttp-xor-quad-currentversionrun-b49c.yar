rule TTP_XOR_QUAD_CurrentVersionRun_b49c {
  strings:
    $key_b49c = { e7 f3 [2] c3 fd [2] e8 d1 [2] c6 f3 [2] d2 e8 [2] dd f2 [2] c3 ef [2] c1 ee [2] da e8 [2] c6 ef [2] da c0 }

  condition:
    any of them
}