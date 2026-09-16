rule TTP_XOR_QUAD_CurrentVersionRun_60da {
  strings:
    $key_60da = { 33 b5 [2] 17 bb [2] 3c 97 [2] 12 b5 [2] 06 ae [2] 09 b4 [2] 17 a9 [2] 15 a8 [2] 0e ae [2] 12 a9 [2] 0e 86 }

  condition:
    any of them
}