rule TTP_XOR_QUAD_CurrentVersionRun_52da {
  strings:
    $key_52da = { 01 b5 [2] 25 bb [2] 0e 97 [2] 20 b5 [2] 34 ae [2] 3b b4 [2] 25 a9 [2] 27 a8 [2] 3c ae [2] 20 a9 [2] 3c 86 }

  condition:
    any of them
}