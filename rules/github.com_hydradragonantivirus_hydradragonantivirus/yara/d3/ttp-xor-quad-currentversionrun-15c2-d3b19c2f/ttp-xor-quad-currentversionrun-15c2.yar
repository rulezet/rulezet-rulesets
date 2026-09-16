rule TTP_XOR_QUAD_CurrentVersionRun_15c2 {
  strings:
    $key_15c2 = { 46 ad [2] 62 a3 [2] 49 8f [2] 67 ad [2] 73 b6 [2] 7c ac [2] 62 b1 [2] 60 b0 [2] 7b b6 [2] 67 b1 [2] 7b 9e }

  condition:
    any of them
}