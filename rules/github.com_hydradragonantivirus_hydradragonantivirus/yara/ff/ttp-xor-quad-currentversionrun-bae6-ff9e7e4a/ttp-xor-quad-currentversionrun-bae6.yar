rule TTP_XOR_QUAD_CurrentVersionRun_bae6 {
  strings:
    $key_bae6 = { e9 89 [2] cd 87 [2] e6 ab [2] c8 89 [2] dc 92 [2] d3 88 [2] cd 95 [2] cf 94 [2] d4 92 [2] c8 95 [2] d4 ba }

  condition:
    any of them
}