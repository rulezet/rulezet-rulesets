rule TTP_XOR_QUAD_CurrentVersionRun_ba19 {
  strings:
    $key_ba19 = { e9 76 [2] cd 78 [2] e6 54 [2] c8 76 [2] dc 6d [2] d3 77 [2] cd 6a [2] cf 6b [2] d4 6d [2] c8 6a [2] d4 45 }

  condition:
    any of them
}