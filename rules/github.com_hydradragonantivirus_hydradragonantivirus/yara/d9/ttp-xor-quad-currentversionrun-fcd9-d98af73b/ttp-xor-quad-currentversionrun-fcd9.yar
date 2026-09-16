rule TTP_XOR_QUAD_CurrentVersionRun_fcd9 {
  strings:
    $key_fcd9 = { af b6 [2] 8b b8 [2] a0 94 [2] 8e b6 [2] 9a ad [2] 95 b7 [2] 8b aa [2] 89 ab [2] 92 ad [2] 8e aa [2] 92 85 }

  condition:
    any of them
}