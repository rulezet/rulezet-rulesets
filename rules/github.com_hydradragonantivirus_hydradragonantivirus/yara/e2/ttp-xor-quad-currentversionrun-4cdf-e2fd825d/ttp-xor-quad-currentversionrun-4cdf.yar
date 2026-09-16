rule TTP_XOR_QUAD_CurrentVersionRun_4cdf {
  strings:
    $key_4cdf = { 1f b0 [2] 3b be [2] 10 92 [2] 3e b0 [2] 2a ab [2] 25 b1 [2] 3b ac [2] 39 ad [2] 22 ab [2] 3e ac [2] 22 83 }

  condition:
    any of them
}