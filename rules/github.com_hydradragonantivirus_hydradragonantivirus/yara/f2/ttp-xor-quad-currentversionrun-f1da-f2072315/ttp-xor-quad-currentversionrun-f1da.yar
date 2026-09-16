rule TTP_XOR_QUAD_CurrentVersionRun_f1da {
  strings:
    $key_f1da = { a2 b5 [2] 86 bb [2] ad 97 [2] 83 b5 [2] 97 ae [2] 98 b4 [2] 86 a9 [2] 84 a8 [2] 9f ae [2] 83 a9 [2] 9f 86 }

  condition:
    any of them
}