rule TTP_XOR_QUAD_CurrentVersionRun_07da {
  strings:
    $key_07da = { 54 b5 [2] 70 bb [2] 5b 97 [2] 75 b5 [2] 61 ae [2] 6e b4 [2] 70 a9 [2] 72 a8 [2] 69 ae [2] 75 a9 [2] 69 86 }

  condition:
    any of them
}