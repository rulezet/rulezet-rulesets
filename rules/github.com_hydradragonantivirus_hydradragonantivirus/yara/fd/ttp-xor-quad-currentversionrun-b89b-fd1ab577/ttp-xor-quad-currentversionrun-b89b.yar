rule TTP_XOR_QUAD_CurrentVersionRun_b89b {
  strings:
    $key_b89b = { eb f4 [2] cf fa [2] e4 d6 [2] ca f4 [2] de ef [2] d1 f5 [2] cf e8 [2] cd e9 [2] d6 ef [2] ca e8 [2] d6 c7 }

  condition:
    any of them
}