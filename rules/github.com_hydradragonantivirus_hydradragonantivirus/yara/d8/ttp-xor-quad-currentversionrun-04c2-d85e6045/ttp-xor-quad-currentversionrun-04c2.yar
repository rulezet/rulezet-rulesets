rule TTP_XOR_QUAD_CurrentVersionRun_04c2 {
  strings:
    $key_04c2 = { 57 ad [2] 73 a3 [2] 58 8f [2] 76 ad [2] 62 b6 [2] 6d ac [2] 73 b1 [2] 71 b0 [2] 6a b6 [2] 76 b1 [2] 6a 9e }

  condition:
    any of them
}