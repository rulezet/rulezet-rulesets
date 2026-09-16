rule TTP_XOR_QUAD_CurrentVersionRun_7af4 {
  strings:
    $key_7af4 = { 29 9b [2] 0d 95 [2] 26 b9 [2] 08 9b [2] 1c 80 [2] 13 9a [2] 0d 87 [2] 0f 86 [2] 14 80 [2] 08 87 [2] 14 a8 }

  condition:
    any of them
}