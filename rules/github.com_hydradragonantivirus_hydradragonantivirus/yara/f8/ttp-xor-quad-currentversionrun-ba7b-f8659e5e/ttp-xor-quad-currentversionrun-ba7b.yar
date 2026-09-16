rule TTP_XOR_QUAD_CurrentVersionRun_ba7b {
  strings:
    $key_ba7b = { e9 14 [2] cd 1a [2] e6 36 [2] c8 14 [2] dc 0f [2] d3 15 [2] cd 08 [2] cf 09 [2] d4 0f [2] c8 08 [2] d4 27 }

  condition:
    any of them
}