rule TTP_XOR_QUAD_CurrentVersionRun_01f4 {
  strings:
    $key_01f4 = { 52 9b [2] 76 95 [2] 5d b9 [2] 73 9b [2] 67 80 [2] 68 9a [2] 76 87 [2] 74 86 [2] 6f 80 [2] 73 87 [2] 6f a8 }

  condition:
    any of them
}