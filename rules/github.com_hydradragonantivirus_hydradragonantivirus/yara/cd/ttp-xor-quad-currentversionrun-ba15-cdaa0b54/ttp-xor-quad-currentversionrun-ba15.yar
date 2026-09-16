rule TTP_XOR_QUAD_CurrentVersionRun_ba15 {
  strings:
    $key_ba15 = { e9 7a [2] cd 74 [2] e6 58 [2] c8 7a [2] dc 61 [2] d3 7b [2] cd 66 [2] cf 67 [2] d4 61 [2] c8 66 [2] d4 49 }

  condition:
    any of them
}