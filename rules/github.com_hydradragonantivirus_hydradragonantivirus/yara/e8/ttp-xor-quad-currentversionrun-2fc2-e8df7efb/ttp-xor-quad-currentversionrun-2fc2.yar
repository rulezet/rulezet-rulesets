rule TTP_XOR_QUAD_CurrentVersionRun_2fc2 {
  strings:
    $key_2fc2 = { 7c ad [2] 58 a3 [2] 73 8f [2] 5d ad [2] 49 b6 [2] 46 ac [2] 58 b1 [2] 5a b0 [2] 41 b6 [2] 5d b1 [2] 41 9e }

  condition:
    any of them
}