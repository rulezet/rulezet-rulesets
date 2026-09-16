rule TTP_XOR_QUAD_CurrentVersionRun_f6c4 {
  strings:
    $key_f6c4 = { a5 ab [2] 81 a5 [2] aa 89 [2] 84 ab [2] 90 b0 [2] 9f aa [2] 81 b7 [2] 83 b6 [2] 98 b0 [2] 84 b7 [2] 98 98 }

  condition:
    any of them
}