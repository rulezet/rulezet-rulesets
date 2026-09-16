rule TTP_XOR_QUAD_CurrentVersionRun_baf4 {
  strings:
    $key_baf4 = { e9 9b [2] cd 95 [2] e6 b9 [2] c8 9b [2] dc 80 [2] d3 9a [2] cd 87 [2] cf 86 [2] d4 80 [2] c8 87 [2] d4 a8 }

  condition:
    any of them
}