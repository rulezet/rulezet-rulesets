rule TTP_XOR_QUAD_CurrentVersionRun_b41e {
  strings:
    $key_b41e = { e7 71 [2] c3 7f [2] e8 53 [2] c6 71 [2] d2 6a [2] dd 70 [2] c3 6d [2] c1 6c [2] da 6a [2] c6 6d [2] da 42 }

  condition:
    any of them
}