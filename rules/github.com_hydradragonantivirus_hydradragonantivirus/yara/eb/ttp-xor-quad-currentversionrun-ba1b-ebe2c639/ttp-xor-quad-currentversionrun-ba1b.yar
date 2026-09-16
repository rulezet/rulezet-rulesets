rule TTP_XOR_QUAD_CurrentVersionRun_ba1b {
  strings:
    $key_ba1b = { e9 74 [2] cd 7a [2] e6 56 [2] c8 74 [2] dc 6f [2] d3 75 [2] cd 68 [2] cf 69 [2] d4 6f [2] c8 68 [2] d4 47 }

  condition:
    any of them
}