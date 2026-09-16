rule TTP_XOR_QUAD_CurrentVersionRun_1f15 {
  strings:
    $key_1f15 = { 4c 7a [2] 68 74 [2] 43 58 [2] 6d 7a [2] 79 61 [2] 76 7b [2] 68 66 [2] 6a 67 [2] 71 61 [2] 6d 66 [2] 71 49 }

  condition:
    any of them
}