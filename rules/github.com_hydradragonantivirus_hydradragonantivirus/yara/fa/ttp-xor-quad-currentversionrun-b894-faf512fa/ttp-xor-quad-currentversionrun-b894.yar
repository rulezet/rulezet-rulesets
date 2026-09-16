rule TTP_XOR_QUAD_CurrentVersionRun_b894 {
  strings:
    $key_b894 = { eb fb [2] cf f5 [2] e4 d9 [2] ca fb [2] de e0 [2] d1 fa [2] cf e7 [2] cd e6 [2] d6 e0 [2] ca e7 [2] d6 c8 }

  condition:
    any of them
}