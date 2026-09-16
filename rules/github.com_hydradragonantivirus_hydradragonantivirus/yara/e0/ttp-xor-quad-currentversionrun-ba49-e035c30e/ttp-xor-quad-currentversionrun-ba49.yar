rule TTP_XOR_QUAD_CurrentVersionRun_ba49 {
  strings:
    $key_ba49 = { e9 26 [2] cd 28 [2] e6 04 [2] c8 26 [2] dc 3d [2] d3 27 [2] cd 3a [2] cf 3b [2] d4 3d [2] c8 3a [2] d4 15 }

  condition:
    any of them
}