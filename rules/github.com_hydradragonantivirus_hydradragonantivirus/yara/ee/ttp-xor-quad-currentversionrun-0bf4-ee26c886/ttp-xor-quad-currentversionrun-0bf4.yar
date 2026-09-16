rule TTP_XOR_QUAD_CurrentVersionRun_0bf4 {
  strings:
    $key_0bf4 = { 58 9b [2] 7c 95 [2] 57 b9 [2] 79 9b [2] 6d 80 [2] 62 9a [2] 7c 87 [2] 7e 86 [2] 65 80 [2] 79 87 [2] 65 a8 }

  condition:
    any of them
}