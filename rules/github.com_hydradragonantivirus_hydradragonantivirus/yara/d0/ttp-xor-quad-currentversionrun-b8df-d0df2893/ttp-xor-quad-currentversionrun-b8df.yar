rule TTP_XOR_QUAD_CurrentVersionRun_b8df {
  strings:
    $key_b8df = { eb b0 [2] cf be [2] e4 92 [2] ca b0 [2] de ab [2] d1 b1 [2] cf ac [2] cd ad [2] d6 ab [2] ca ac [2] d6 83 }

  condition:
    any of them
}