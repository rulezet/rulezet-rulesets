rule TTP_XOR_QUAD_CurrentVersionRun_30df {
  strings:
    $key_30df = { 63 b0 [2] 47 be [2] 6c 92 [2] 42 b0 [2] 56 ab [2] 59 b1 [2] 47 ac [2] 45 ad [2] 5e ab [2] 42 ac [2] 5e 83 }

  condition:
    any of them
}