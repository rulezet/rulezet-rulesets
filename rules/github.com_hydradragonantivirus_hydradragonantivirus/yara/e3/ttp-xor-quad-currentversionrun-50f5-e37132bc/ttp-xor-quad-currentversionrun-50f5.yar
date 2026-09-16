rule TTP_XOR_QUAD_CurrentVersionRun_50f5 {
  strings:
    $key_50f5 = { 03 9a [2] 27 94 [2] 0c b8 [2] 22 9a [2] 36 81 [2] 39 9b [2] 27 86 [2] 25 87 [2] 3e 81 [2] 22 86 [2] 3e a9 }

  condition:
    any of them
}