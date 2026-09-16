rule TTP_XOR_QUAD_CurrentVersionRun_76c3 {
  strings:
    $key_76c3 = { 25 ac [2] 01 a2 [2] 2a 8e [2] 04 ac [2] 10 b7 [2] 1f ad [2] 01 b0 [2] 03 b1 [2] 18 b7 [2] 04 b0 [2] 18 9f }

  condition:
    any of them
}