rule TTP_XOR_QUAD_CurrentVersionRun_40c2 {
  strings:
    $key_40c2 = { 13 ad [2] 37 a3 [2] 1c 8f [2] 32 ad [2] 26 b6 [2] 29 ac [2] 37 b1 [2] 35 b0 [2] 2e b6 [2] 32 b1 [2] 2e 9e }

  condition:
    any of them
}