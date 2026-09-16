rule TTP_XOR_QUAD_CurrentVersionRun_d1da {
  strings:
    $key_d1da = { 82 b5 [2] a6 bb [2] 8d 97 [2] a3 b5 [2] b7 ae [2] b8 b4 [2] a6 a9 [2] a4 a8 [2] bf ae [2] a3 a9 [2] bf 86 }

  condition:
    any of them
}