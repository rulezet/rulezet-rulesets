rule TTP_XOR_QUAD_CurrentVersionRun_b727 {
  strings:
    $key_b727 = { e4 48 [2] c0 46 [2] eb 6a [2] c5 48 [2] d1 53 [2] de 49 [2] c0 54 [2] c2 55 [2] d9 53 [2] c5 54 [2] d9 7b }

  condition:
    any of them
}