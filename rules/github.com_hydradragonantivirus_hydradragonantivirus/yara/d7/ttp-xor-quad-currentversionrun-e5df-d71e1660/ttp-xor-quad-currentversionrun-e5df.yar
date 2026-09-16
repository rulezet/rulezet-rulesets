rule TTP_XOR_QUAD_CurrentVersionRun_e5df {
  strings:
    $key_e5df = { b6 b0 [2] 92 be [2] b9 92 [2] 97 b0 [2] 83 ab [2] 8c b1 [2] 92 ac [2] 90 ad [2] 8b ab [2] 97 ac [2] 8b 83 }

  condition:
    any of them
}