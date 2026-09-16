rule TTP_XOR_QUAD_CurrentVersionRun_0ff4 {
  strings:
    $key_0ff4 = { 5c 9b [2] 78 95 [2] 53 b9 [2] 7d 9b [2] 69 80 [2] 66 9a [2] 78 87 [2] 7a 86 [2] 61 80 [2] 7d 87 [2] 61 a8 }

  condition:
    any of them
}