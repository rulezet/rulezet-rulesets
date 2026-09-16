rule TTP_XOR_QUAD_CurrentVersionRun_ecdf {
  strings:
    $key_ecdf = { bf b0 [2] 9b be [2] b0 92 [2] 9e b0 [2] 8a ab [2] 85 b1 [2] 9b ac [2] 99 ad [2] 82 ab [2] 9e ac [2] 82 83 }

  condition:
    any of them
}