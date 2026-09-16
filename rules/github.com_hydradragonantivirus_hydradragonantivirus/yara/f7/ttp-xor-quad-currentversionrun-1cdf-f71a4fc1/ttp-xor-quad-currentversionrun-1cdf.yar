rule TTP_XOR_QUAD_CurrentVersionRun_1cdf {
  strings:
    $key_1cdf = { 4f b0 [2] 6b be [2] 40 92 [2] 6e b0 [2] 7a ab [2] 75 b1 [2] 6b ac [2] 69 ad [2] 72 ab [2] 6e ac [2] 72 83 }

  condition:
    any of them
}