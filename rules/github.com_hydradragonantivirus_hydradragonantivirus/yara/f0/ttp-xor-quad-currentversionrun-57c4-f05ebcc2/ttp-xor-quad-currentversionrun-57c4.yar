rule TTP_XOR_QUAD_CurrentVersionRun_57c4 {
  strings:
    $key_57c4 = { 04 ab [2] 20 a5 [2] 0b 89 [2] 25 ab [2] 31 b0 [2] 3e aa [2] 20 b7 [2] 22 b6 [2] 39 b0 [2] 25 b7 [2] 39 98 }

  condition:
    any of them
}