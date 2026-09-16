rule TTP_XOR_QUAD_CurrentVersionRun_def5 {
  strings:
    $key_def5 = { 8d 9a [2] a9 94 [2] 82 b8 [2] ac 9a [2] b8 81 [2] b7 9b [2] a9 86 [2] ab 87 [2] b0 81 [2] ac 86 [2] b0 a9 }

  condition:
    any of them
}