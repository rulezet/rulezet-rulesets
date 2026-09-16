rule TTP_XOR_QUAD_CurrentVersionRun_ba8d {
  strings:
    $key_ba8d = { e9 e2 [2] cd ec [2] e6 c0 [2] c8 e2 [2] dc f9 [2] d3 e3 [2] cd fe [2] cf ff [2] d4 f9 [2] c8 fe [2] d4 d1 }

  condition:
    any of them
}