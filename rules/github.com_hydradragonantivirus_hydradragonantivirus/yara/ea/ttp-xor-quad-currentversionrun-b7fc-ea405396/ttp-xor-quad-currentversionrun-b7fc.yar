rule TTP_XOR_QUAD_CurrentVersionRun_b7fc {
  strings:
    $key_b7fc = { e4 93 [2] c0 9d [2] eb b1 [2] c5 93 [2] d1 88 [2] de 92 [2] c0 8f [2] c2 8e [2] d9 88 [2] c5 8f [2] d9 a0 }

  condition:
    any of them
}