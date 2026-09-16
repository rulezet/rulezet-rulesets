rule TTP_XOR_QUAD_CurrentVersionRun_4e15 {
  strings:
    $key_4e15 = { 1d 7a [2] 39 74 [2] 12 58 [2] 3c 7a [2] 28 61 [2] 27 7b [2] 39 66 [2] 3b 67 [2] 20 61 [2] 3c 66 [2] 20 49 }

  condition:
    any of them
}