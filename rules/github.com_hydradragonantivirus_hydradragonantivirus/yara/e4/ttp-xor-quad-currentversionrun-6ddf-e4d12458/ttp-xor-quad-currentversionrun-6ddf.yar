rule TTP_XOR_QUAD_CurrentVersionRun_6ddf {
  strings:
    $key_6ddf = { 3e b0 [2] 1a be [2] 31 92 [2] 1f b0 [2] 0b ab [2] 04 b1 [2] 1a ac [2] 18 ad [2] 03 ab [2] 1f ac [2] 03 83 }

  condition:
    any of them
}