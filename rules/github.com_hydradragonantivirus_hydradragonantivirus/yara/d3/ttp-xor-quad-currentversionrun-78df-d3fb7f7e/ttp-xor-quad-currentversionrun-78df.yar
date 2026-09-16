rule TTP_XOR_QUAD_CurrentVersionRun_78df {
  strings:
    $key_78df = { 2b b0 [2] 0f be [2] 24 92 [2] 0a b0 [2] 1e ab [2] 11 b1 [2] 0f ac [2] 0d ad [2] 16 ab [2] 0a ac [2] 16 83 }

  condition:
    any of them
}