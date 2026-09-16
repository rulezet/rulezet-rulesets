rule TTP_XOR_QUAD_CurrentVersionRun_17c4 {
  strings:
    $key_17c4 = { 44 ab [2] 60 a5 [2] 4b 89 [2] 65 ab [2] 71 b0 [2] 7e aa [2] 60 b7 [2] 62 b6 [2] 79 b0 [2] 65 b7 [2] 79 98 }

  condition:
    any of them
}