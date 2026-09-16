rule TTP_XOR_QUAD_CurrentVersionRun_a3c4 {
  strings:
    $key_a3c4 = { f0 ab [2] d4 a5 [2] ff 89 [2] d1 ab [2] c5 b0 [2] ca aa [2] d4 b7 [2] d6 b6 [2] cd b0 [2] d1 b7 [2] cd 98 }

  condition:
    any of them
}