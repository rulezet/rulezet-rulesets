rule TTP_XOR_QUAD_CurrentVersionRun_35c2 {
  strings:
    $key_35c2 = { 66 ad [2] 42 a3 [2] 69 8f [2] 47 ad [2] 53 b6 [2] 5c ac [2] 42 b1 [2] 40 b0 [2] 5b b6 [2] 47 b1 [2] 5b 9e }

  condition:
    any of them
}