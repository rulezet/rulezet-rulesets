rule TTP_XOR_QUAD_CurrentVersionRun_2ac2 {
  strings:
    $key_2ac2 = { 79 ad [2] 5d a3 [2] 76 8f [2] 58 ad [2] 4c b6 [2] 43 ac [2] 5d b1 [2] 5f b0 [2] 44 b6 [2] 58 b1 [2] 44 9e }

  condition:
    any of them
}