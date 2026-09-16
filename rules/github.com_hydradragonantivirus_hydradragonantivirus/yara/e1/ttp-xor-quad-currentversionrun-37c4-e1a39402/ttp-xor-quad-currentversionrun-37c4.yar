rule TTP_XOR_QUAD_CurrentVersionRun_37c4 {
  strings:
    $key_37c4 = { 64 ab [2] 40 a5 [2] 6b 89 [2] 45 ab [2] 51 b0 [2] 5e aa [2] 40 b7 [2] 42 b6 [2] 59 b0 [2] 45 b7 [2] 59 98 }

  condition:
    any of them
}