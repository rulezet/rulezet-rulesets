rule TTP_XOR_QUAD_CurrentVersionRun_b750 {
  strings:
    $key_b750 = { e4 3f [2] c0 31 [2] eb 1d [2] c5 3f [2] d1 24 [2] de 3e [2] c0 23 [2] c2 22 [2] d9 24 [2] c5 23 [2] d9 0c }

  condition:
    any of them
}