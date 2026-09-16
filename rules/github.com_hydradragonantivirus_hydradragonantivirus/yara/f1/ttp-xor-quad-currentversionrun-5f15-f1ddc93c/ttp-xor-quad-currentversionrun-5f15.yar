rule TTP_XOR_QUAD_CurrentVersionRun_5f15 {
  strings:
    $key_5f15 = { 0c 7a [2] 28 74 [2] 03 58 [2] 2d 7a [2] 39 61 [2] 36 7b [2] 28 66 [2] 2a 67 [2] 31 61 [2] 2d 66 [2] 31 49 }

  condition:
    any of them
}