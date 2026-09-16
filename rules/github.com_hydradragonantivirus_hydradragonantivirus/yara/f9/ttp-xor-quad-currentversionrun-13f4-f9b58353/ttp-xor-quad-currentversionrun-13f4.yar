rule TTP_XOR_QUAD_CurrentVersionRun_13f4 {
  strings:
    $key_13f4 = { 40 9b [2] 64 95 [2] 4f b9 [2] 61 9b [2] 75 80 [2] 7a 9a [2] 64 87 [2] 66 86 [2] 7d 80 [2] 61 87 [2] 7d a8 }

  condition:
    any of them
}