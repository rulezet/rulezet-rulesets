rule TTP_XOR_QUAD_CurrentVersionRun_22c2 {
  strings:
    $key_22c2 = { 71 ad [2] 55 a3 [2] 7e 8f [2] 50 ad [2] 44 b6 [2] 4b ac [2] 55 b1 [2] 57 b0 [2] 4c b6 [2] 50 b1 [2] 4c 9e }

  condition:
    any of them
}