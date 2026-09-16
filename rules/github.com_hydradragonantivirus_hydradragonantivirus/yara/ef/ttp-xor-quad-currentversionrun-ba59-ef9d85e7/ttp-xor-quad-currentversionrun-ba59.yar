rule TTP_XOR_QUAD_CurrentVersionRun_ba59 {
  strings:
    $key_ba59 = { e9 36 [2] cd 38 [2] e6 14 [2] c8 36 [2] dc 2d [2] d3 37 [2] cd 2a [2] cf 2b [2] d4 2d [2] c8 2a [2] d4 05 }

  condition:
    any of them
}