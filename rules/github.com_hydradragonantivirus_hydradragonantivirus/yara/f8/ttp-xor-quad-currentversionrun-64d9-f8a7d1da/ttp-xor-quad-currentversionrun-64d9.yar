rule TTP_XOR_QUAD_CurrentVersionRun_64d9 {
  strings:
    $key_64d9 = { 37 b6 [2] 13 b8 [2] 38 94 [2] 16 b6 [2] 02 ad [2] 0d b7 [2] 13 aa [2] 11 ab [2] 0a ad [2] 16 aa [2] 0a 85 }

  condition:
    any of them
}