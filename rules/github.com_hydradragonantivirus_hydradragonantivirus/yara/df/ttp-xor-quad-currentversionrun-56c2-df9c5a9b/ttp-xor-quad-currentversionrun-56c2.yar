rule TTP_XOR_QUAD_CurrentVersionRun_56c2 {
  strings:
    $key_56c2 = { 05 ad [2] 21 a3 [2] 0a 8f [2] 24 ad [2] 30 b6 [2] 3f ac [2] 21 b1 [2] 23 b0 [2] 38 b6 [2] 24 b1 [2] 38 9e }

  condition:
    any of them
}