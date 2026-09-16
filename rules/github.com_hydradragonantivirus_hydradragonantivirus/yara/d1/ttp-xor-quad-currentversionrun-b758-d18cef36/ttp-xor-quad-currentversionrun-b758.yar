rule TTP_XOR_QUAD_CurrentVersionRun_b758 {
  strings:
    $key_b758 = { e4 37 [2] c0 39 [2] eb 15 [2] c5 37 [2] d1 2c [2] de 36 [2] c0 2b [2] c2 2a [2] d9 2c [2] c5 2b [2] d9 04 }

  condition:
    any of them
}