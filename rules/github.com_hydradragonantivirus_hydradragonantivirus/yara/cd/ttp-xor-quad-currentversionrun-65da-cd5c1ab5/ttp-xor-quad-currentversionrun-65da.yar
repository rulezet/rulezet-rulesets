rule TTP_XOR_QUAD_CurrentVersionRun_65da {
  strings:
    $key_65da = { 36 b5 [2] 12 bb [2] 39 97 [2] 17 b5 [2] 03 ae [2] 0c b4 [2] 12 a9 [2] 10 a8 [2] 0b ae [2] 17 a9 [2] 0b 86 }

  condition:
    any of them
}