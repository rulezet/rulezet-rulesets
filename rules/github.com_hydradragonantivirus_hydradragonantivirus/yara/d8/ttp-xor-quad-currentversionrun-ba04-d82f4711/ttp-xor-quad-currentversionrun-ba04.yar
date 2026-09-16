rule TTP_XOR_QUAD_CurrentVersionRun_ba04 {
  strings:
    $key_ba04 = { e9 6b [2] cd 65 [2] e6 49 [2] c8 6b [2] dc 70 [2] d3 6a [2] cd 77 [2] cf 76 [2] d4 70 [2] c8 77 [2] d4 58 }

  condition:
    any of them
}