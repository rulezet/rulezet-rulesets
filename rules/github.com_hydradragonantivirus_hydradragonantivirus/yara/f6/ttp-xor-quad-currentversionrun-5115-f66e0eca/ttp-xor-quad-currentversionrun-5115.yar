rule TTP_XOR_QUAD_CurrentVersionRun_5115 {
  strings:
    $key_5115 = { 02 7a [2] 26 74 [2] 0d 58 [2] 23 7a [2] 37 61 [2] 38 7b [2] 26 66 [2] 24 67 [2] 3f 61 [2] 23 66 [2] 3f 49 }

  condition:
    any of them
}