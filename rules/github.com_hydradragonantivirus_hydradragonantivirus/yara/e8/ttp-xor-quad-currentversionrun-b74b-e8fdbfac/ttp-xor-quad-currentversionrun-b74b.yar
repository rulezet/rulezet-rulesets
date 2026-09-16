rule TTP_XOR_QUAD_CurrentVersionRun_b74b {
  strings:
    $key_b74b = { e4 24 [2] c0 2a [2] eb 06 [2] c5 24 [2] d1 3f [2] de 25 [2] c0 38 [2] c2 39 [2] d9 3f [2] c5 38 [2] d9 17 }

  condition:
    any of them
}