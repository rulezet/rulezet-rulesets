rule TTP_XOR_QUAD_CurrentVersionRun_ba4e {
  strings:
    $key_ba4e = { e9 21 [2] cd 2f [2] e6 03 [2] c8 21 [2] dc 3a [2] d3 20 [2] cd 3d [2] cf 3c [2] d4 3a [2] c8 3d [2] d4 12 }

  condition:
    any of them
}