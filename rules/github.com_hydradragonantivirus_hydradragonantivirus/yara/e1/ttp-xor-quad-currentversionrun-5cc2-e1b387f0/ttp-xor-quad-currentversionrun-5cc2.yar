rule TTP_XOR_QUAD_CurrentVersionRun_5cc2 {
  strings:
    $key_5cc2 = { 0f ad [2] 2b a3 [2] 00 8f [2] 2e ad [2] 3a b6 [2] 35 ac [2] 2b b1 [2] 29 b0 [2] 32 b6 [2] 2e b1 [2] 32 9e }

  condition:
    any of them
}