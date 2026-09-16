rule TTP_XOR_QUAD_CurrentVersionRun_42c2 {
  strings:
    $key_42c2 = { 11 ad [2] 35 a3 [2] 1e 8f [2] 30 ad [2] 24 b6 [2] 2b ac [2] 35 b1 [2] 37 b0 [2] 2c b6 [2] 30 b1 [2] 2c 9e }

  condition:
    any of them
}