rule TTP_XOR_QUAD_CurrentVersionRun_b1f1 {
  strings:
    $key_b1f1 = { e2 9e [2] c6 90 [2] ed bc [2] c3 9e [2] d7 85 [2] d8 9f [2] c6 82 [2] c4 83 [2] df 85 [2] c3 82 [2] df ad }

  condition:
    any of them
}