rule TTP_XOR_QUAD_CurrentVersionRun_13f5 {
  strings:
    $key_13f5 = { 40 9a [2] 64 94 [2] 4f b8 [2] 61 9a [2] 75 81 [2] 7a 9b [2] 64 86 [2] 66 87 [2] 7d 81 [2] 61 86 [2] 7d a9 }

  condition:
    any of them
}