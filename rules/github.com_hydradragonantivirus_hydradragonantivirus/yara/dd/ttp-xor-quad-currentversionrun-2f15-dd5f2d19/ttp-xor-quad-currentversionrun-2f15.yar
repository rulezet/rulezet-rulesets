rule TTP_XOR_QUAD_CurrentVersionRun_2f15 {
  strings:
    $key_2f15 = { 7c 7a [2] 58 74 [2] 73 58 [2] 5d 7a [2] 49 61 [2] 46 7b [2] 58 66 [2] 5a 67 [2] 41 61 [2] 5d 66 [2] 41 49 }

  condition:
    any of them
}