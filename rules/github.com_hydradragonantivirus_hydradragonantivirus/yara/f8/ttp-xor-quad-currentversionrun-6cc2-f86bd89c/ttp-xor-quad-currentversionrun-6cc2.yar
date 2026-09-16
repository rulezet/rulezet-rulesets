rule TTP_XOR_QUAD_CurrentVersionRun_6cc2 {
  strings:
    $key_6cc2 = { 3f ad [2] 1b a3 [2] 30 8f [2] 1e ad [2] 0a b6 [2] 05 ac [2] 1b b1 [2] 19 b0 [2] 02 b6 [2] 1e b1 [2] 02 9e }

  condition:
    any of them
}