rule TTP_XOR_QUAD_CurrentVersionRun_40d9 {
  strings:
    $key_40d9 = { 13 b6 [2] 37 b8 [2] 1c 94 [2] 32 b6 [2] 26 ad [2] 29 b7 [2] 37 aa [2] 35 ab [2] 2e ad [2] 32 aa [2] 2e 85 }

  condition:
    any of them
}