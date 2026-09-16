rule TTP_XOR_QUAD_CurrentVersionRun_ba8b {
  strings:
    $key_ba8b = { e9 e4 [2] cd ea [2] e6 c6 [2] c8 e4 [2] dc ff [2] d3 e5 [2] cd f8 [2] cf f9 [2] d4 ff [2] c8 f8 [2] d4 d7 }

  condition:
    any of them
}