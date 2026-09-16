rule TTP_XOR_QUAD_CurrentVersionRun_5fe8 {
  strings:
    $key_5fe8 = { 0c 87 [2] 28 89 [2] 03 a5 [2] 2d 87 [2] 39 9c [2] 36 86 [2] 28 9b [2] 2a 9a [2] 31 9c [2] 2d 9b [2] 31 b4 }

  condition:
    any of them
}