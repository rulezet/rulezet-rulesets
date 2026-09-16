rule TTP_XOR_QUAD_CurrentVersionRun_ba08 {
  strings:
    $key_ba08 = { e9 67 [2] cd 69 [2] e6 45 [2] c8 67 [2] dc 7c [2] d3 66 [2] cd 7b [2] cf 7a [2] d4 7c [2] c8 7b [2] d4 54 }

  condition:
    any of them
}