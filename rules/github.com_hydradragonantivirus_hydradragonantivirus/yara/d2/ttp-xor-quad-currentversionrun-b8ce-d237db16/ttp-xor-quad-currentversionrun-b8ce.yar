rule TTP_XOR_QUAD_CurrentVersionRun_b8ce {
  strings:
    $key_b8ce = { eb a1 [2] cf af [2] e4 83 [2] ca a1 [2] de ba [2] d1 a0 [2] cf bd [2] cd bc [2] d6 ba [2] ca bd [2] d6 92 }

  condition:
    any of them
}