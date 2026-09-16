rule TTP_XOR_QUAD_CurrentVersionRun_38d9 {
  strings:
    $key_38d9 = { 6b b6 [2] 4f b8 [2] 64 94 [2] 4a b6 [2] 5e ad [2] 51 b7 [2] 4f aa [2] 4d ab [2] 56 ad [2] 4a aa [2] 56 85 }

  condition:
    any of them
}