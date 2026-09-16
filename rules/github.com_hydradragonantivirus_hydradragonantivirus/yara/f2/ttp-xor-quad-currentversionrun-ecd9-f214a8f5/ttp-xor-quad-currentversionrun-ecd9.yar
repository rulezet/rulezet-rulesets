rule TTP_XOR_QUAD_CurrentVersionRun_ecd9 {
  strings:
    $key_ecd9 = { bf b6 [2] 9b b8 [2] b0 94 [2] 9e b6 [2] 8a ad [2] 85 b7 [2] 9b aa [2] 99 ab [2] 82 ad [2] 9e aa [2] 82 85 }

  condition:
    any of them
}