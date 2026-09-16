rule TTP_XOR_QUAD_CurrentVersionRun_baf1 {
  strings:
    $key_baf1 = { e9 9e [2] cd 90 [2] e6 bc [2] c8 9e [2] dc 85 [2] d3 9f [2] cd 82 [2] cf 83 [2] d4 85 [2] c8 82 [2] d4 ad }

  condition:
    any of them
}