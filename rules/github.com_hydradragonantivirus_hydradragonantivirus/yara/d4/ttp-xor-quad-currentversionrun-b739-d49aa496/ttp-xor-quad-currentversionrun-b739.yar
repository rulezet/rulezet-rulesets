rule TTP_XOR_QUAD_CurrentVersionRun_b739 {
  strings:
    $key_b739 = { e4 56 [2] c0 58 [2] eb 74 [2] c5 56 [2] d1 4d [2] de 57 [2] c0 4a [2] c2 4b [2] d9 4d [2] c5 4a [2] d9 65 }

  condition:
    any of them
}