rule TTP_XOR_QUAD_CurrentVersionRun_bacd {
  strings:
    $key_bacd = { e9 a2 [2] cd ac [2] e6 80 [2] c8 a2 [2] dc b9 [2] d3 a3 [2] cd be [2] cf bf [2] d4 b9 [2] c8 be [2] d4 91 }

  condition:
    any of them
}