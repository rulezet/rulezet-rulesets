rule TTP_XOR_QUAD_CurrentVersionRun_25d8 {
  strings:
    $key_25d8 = { 76 b7 [2] 52 b9 [2] 79 95 [2] 57 b7 [2] 43 ac [2] 4c b6 [2] 52 ab [2] 50 aa [2] 4b ac [2] 57 ab [2] 4b 84 }

  condition:
    any of them
}