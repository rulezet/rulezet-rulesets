rule TTP_XOR_QUAD_CurrentVersionRun_41da {
  strings:
    $key_41da = { 12 b5 [2] 36 bb [2] 1d 97 [2] 33 b5 [2] 27 ae [2] 28 b4 [2] 36 a9 [2] 34 a8 [2] 2f ae [2] 33 a9 [2] 2f 86 }

  condition:
    any of them
}