rule TTP_XOR_QUAD_CurrentVersionRun_def4 {
  strings:
    $key_def4 = { 8d 9b [2] a9 95 [2] 82 b9 [2] ac 9b [2] b8 80 [2] b7 9a [2] a9 87 [2] ab 86 [2] b0 80 [2] ac 87 [2] b0 a8 }

  condition:
    any of them
}