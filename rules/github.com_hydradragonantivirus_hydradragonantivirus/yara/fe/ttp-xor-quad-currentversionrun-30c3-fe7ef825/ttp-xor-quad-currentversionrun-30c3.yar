rule TTP_XOR_QUAD_CurrentVersionRun_30c3 {
  strings:
    $key_30c3 = { 63 ac [2] 47 a2 [2] 6c 8e [2] 42 ac [2] 56 b7 [2] 59 ad [2] 47 b0 [2] 45 b1 [2] 5e b7 [2] 42 b0 [2] 5e 9f }

  condition:
    any of them
}