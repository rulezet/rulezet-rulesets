rule TTP_XOR_QUAD_CurrentVersionRun_15da {
  strings:
    $key_15da = { 46 b5 [2] 62 bb [2] 49 97 [2] 67 b5 [2] 73 ae [2] 7c b4 [2] 62 a9 [2] 60 a8 [2] 7b ae [2] 67 a9 [2] 7b 86 }

  condition:
    any of them
}