rule TTP_XOR_QUAD_CurrentVersionRun_30c2 {
  strings:
    $key_30c2 = { 63 ad [2] 47 a3 [2] 6c 8f [2] 42 ad [2] 56 b6 [2] 59 ac [2] 47 b1 [2] 45 b0 [2] 5e b6 [2] 42 b1 [2] 5e 9e }

  condition:
    any of them
}