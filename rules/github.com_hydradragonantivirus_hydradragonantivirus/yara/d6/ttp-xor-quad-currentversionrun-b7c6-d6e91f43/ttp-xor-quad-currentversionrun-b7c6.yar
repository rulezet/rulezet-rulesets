rule TTP_XOR_QUAD_CurrentVersionRun_b7c6 {
  strings:
    $key_b7c6 = { e4 a9 [2] c0 a7 [2] eb 8b [2] c5 a9 [2] d1 b2 [2] de a8 [2] c0 b5 [2] c2 b4 [2] d9 b2 [2] c5 b5 [2] d9 9a }

  condition:
    any of them
}