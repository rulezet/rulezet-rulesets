rule TTP_XOR_QUAD_CurrentVersionRun_ba6b {
  strings:
    $key_ba6b = { e9 04 [2] cd 0a [2] e6 26 [2] c8 04 [2] dc 1f [2] d3 05 [2] cd 18 [2] cf 19 [2] d4 1f [2] c8 18 [2] d4 37 }

  condition:
    any of them
}