rule TTP_XOR_QUAD_CurrentVersionRun_46da {
  strings:
    $key_46da = { 15 b5 [2] 31 bb [2] 1a 97 [2] 34 b5 [2] 20 ae [2] 2f b4 [2] 31 a9 [2] 33 a8 [2] 28 ae [2] 34 a9 [2] 28 86 }

  condition:
    any of them
}