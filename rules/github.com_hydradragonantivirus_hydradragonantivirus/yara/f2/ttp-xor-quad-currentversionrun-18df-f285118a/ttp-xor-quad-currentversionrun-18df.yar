rule TTP_XOR_QUAD_CurrentVersionRun_18df {
  strings:
    $key_18df = { 4b b0 [2] 6f be [2] 44 92 [2] 6a b0 [2] 7e ab [2] 71 b1 [2] 6f ac [2] 6d ad [2] 76 ab [2] 6a ac [2] 76 83 }

  condition:
    any of them
}