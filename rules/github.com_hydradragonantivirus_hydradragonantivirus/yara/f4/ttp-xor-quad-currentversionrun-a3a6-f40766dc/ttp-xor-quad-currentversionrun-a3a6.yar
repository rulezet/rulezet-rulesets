rule TTP_XOR_QUAD_CurrentVersionRun_a3a6 {
  strings:
    $key_a3a6 = { f0 c9 [2] d4 c7 [2] ff eb [2] d1 c9 [2] c5 d2 [2] ca c8 [2] d4 d5 [2] d6 d4 [2] cd d2 [2] d1 d5 [2] cd fa }

  condition:
    any of them
}