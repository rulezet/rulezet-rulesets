rule TTP_XOR_QUAD_CurrentVersionRun_b888 {
  strings:
    $key_b888 = { eb e7 [2] cf e9 [2] e4 c5 [2] ca e7 [2] de fc [2] d1 e6 [2] cf fb [2] cd fa [2] d6 fc [2] ca fb [2] d6 d4 }

  condition:
    any of them
}