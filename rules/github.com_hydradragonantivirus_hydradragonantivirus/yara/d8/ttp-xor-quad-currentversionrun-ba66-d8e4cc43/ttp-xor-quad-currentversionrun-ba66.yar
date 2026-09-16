rule TTP_XOR_QUAD_CurrentVersionRun_ba66 {
  strings:
    $key_ba66 = { e9 09 [2] cd 07 [2] e6 2b [2] c8 09 [2] dc 12 [2] d3 08 [2] cd 15 [2] cf 14 [2] d4 12 [2] c8 15 [2] d4 3a }

  condition:
    any of them
}