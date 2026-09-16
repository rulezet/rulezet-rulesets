rule TTP_XOR_QUAD_CurrentVersionRun_ba38 {
  strings:
    $key_ba38 = { e9 57 [2] cd 59 [2] e6 75 [2] c8 57 [2] dc 4c [2] d3 56 [2] cd 4b [2] cf 4a [2] d4 4c [2] c8 4b [2] d4 64 }

  condition:
    any of them
}