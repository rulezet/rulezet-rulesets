rule TTP_XOR_QUAD_CurrentVersionRun_abdf {
  strings:
    $key_abdf = { f8 b0 [2] dc be [2] f7 92 [2] d9 b0 [2] cd ab [2] c2 b1 [2] dc ac [2] de ad [2] c5 ab [2] d9 ac [2] c5 83 }

  condition:
    any of them
}