rule TTP_XOR_QUAD_CurrentVersionRun_08d9 {
  strings:
    $key_08d9 = { 5b b6 [2] 7f b8 [2] 54 94 [2] 7a b6 [2] 6e ad [2] 61 b7 [2] 7f aa [2] 7d ab [2] 66 ad [2] 7a aa [2] 66 85 }

  condition:
    any of them
}