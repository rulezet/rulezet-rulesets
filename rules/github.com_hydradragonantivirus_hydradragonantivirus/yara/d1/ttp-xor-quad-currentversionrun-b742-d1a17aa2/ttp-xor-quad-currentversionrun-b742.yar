rule TTP_XOR_QUAD_CurrentVersionRun_b742 {
  strings:
    $key_b742 = { e4 2d [2] c0 23 [2] eb 0f [2] c5 2d [2] d1 36 [2] de 2c [2] c0 31 [2] c2 30 [2] d9 36 [2] c5 31 [2] d9 1e }

  condition:
    any of them
}