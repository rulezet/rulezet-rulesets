rule TTP_XOR_QUAD_CurrentVersionRun_40c4 {
  strings:
    $key_40c4 = { 13 ab [2] 37 a5 [2] 1c 89 [2] 32 ab [2] 26 b0 [2] 29 aa [2] 37 b7 [2] 35 b6 [2] 2e b0 [2] 32 b7 [2] 2e 98 }

  condition:
    any of them
}