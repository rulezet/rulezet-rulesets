rule TTP_XOR_QUAD_CurrentVersionRun_4ef4 {
  strings:
    $key_4ef4 = { 1d 9b [2] 39 95 [2] 12 b9 [2] 3c 9b [2] 28 80 [2] 27 9a [2] 39 87 [2] 3b 86 [2] 20 80 [2] 3c 87 [2] 20 a8 }

  condition:
    any of them
}