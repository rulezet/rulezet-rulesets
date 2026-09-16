rule TTP_XOR_QUAD_CurrentVersionRun_3124 {
  strings:
    $key_3124 = { 62 4b [2] 46 45 [2] 6d 69 [2] 43 4b [2] 57 50 [2] 58 4a [2] 46 57 [2] 44 56 [2] 5f 50 [2] 43 57 [2] 5f 78 }

  condition:
    any of them
}