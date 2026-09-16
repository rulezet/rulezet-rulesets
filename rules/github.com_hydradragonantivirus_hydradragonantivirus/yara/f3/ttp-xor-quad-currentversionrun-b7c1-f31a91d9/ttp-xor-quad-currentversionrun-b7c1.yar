rule TTP_XOR_QUAD_CurrentVersionRun_b7c1 {
  strings:
    $key_b7c1 = { e4 ae [2] c0 a0 [2] eb 8c [2] c5 ae [2] d1 b5 [2] de af [2] c0 b2 [2] c2 b3 [2] d9 b5 [2] c5 b2 [2] d9 9d }

  condition:
    any of them
}