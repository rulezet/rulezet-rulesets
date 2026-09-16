rule TTP_XOR_QUAD_CurrentVersionRun_74c2 {
  strings:
    $key_74c2 = { 27 ad [2] 03 a3 [2] 28 8f [2] 06 ad [2] 12 b6 [2] 1d ac [2] 03 b1 [2] 01 b0 [2] 1a b6 [2] 06 b1 [2] 1a 9e }

  condition:
    any of them
}