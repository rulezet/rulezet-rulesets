rule TTP_XOR_QUAD_CurrentVersionRun_ba1a {
  strings:
    $key_ba1a = { e9 75 [2] cd 7b [2] e6 57 [2] c8 75 [2] dc 6e [2] d3 74 [2] cd 69 [2] cf 68 [2] d4 6e [2] c8 69 [2] d4 46 }

  condition:
    any of them
}