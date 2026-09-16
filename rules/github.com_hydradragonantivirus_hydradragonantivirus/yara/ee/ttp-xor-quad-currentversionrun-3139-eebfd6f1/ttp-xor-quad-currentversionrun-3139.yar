rule TTP_XOR_QUAD_CurrentVersionRun_3139 {
  strings:
    $key_3139 = { 62 56 [2] 46 58 [2] 6d 74 [2] 43 56 [2] 57 4d [2] 58 57 [2] 46 4a [2] 44 4b [2] 5f 4d [2] 43 4a [2] 5f 65 }

  condition:
    any of them
}