rule TTP_XOR_QUAD_CurrentVersionRun_ba25 {
  strings:
    $key_ba25 = { e9 4a [2] cd 44 [2] e6 68 [2] c8 4a [2] dc 51 [2] d3 4b [2] cd 56 [2] cf 57 [2] d4 51 [2] c8 56 [2] d4 79 }

  condition:
    any of them
}