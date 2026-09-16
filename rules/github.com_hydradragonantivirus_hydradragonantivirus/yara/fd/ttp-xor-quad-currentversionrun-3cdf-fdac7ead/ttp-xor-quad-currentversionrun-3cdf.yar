rule TTP_XOR_QUAD_CurrentVersionRun_3cdf {
  strings:
    $key_3cdf = { 6f b0 [2] 4b be [2] 60 92 [2] 4e b0 [2] 5a ab [2] 55 b1 [2] 4b ac [2] 49 ad [2] 52 ab [2] 4e ac [2] 52 83 }

  condition:
    any of them
}