rule TTP_XOR_QUAD_CurrentVersionRun_45d8 {
  strings:
    $key_45d8 = { 16 b7 [2] 32 b9 [2] 19 95 [2] 37 b7 [2] 23 ac [2] 2c b6 [2] 32 ab [2] 30 aa [2] 2b ac [2] 37 ab [2] 2b 84 }

  condition:
    any of them
}