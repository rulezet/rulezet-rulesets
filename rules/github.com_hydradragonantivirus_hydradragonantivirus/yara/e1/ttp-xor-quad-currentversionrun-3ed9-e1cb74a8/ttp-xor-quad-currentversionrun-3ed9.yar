rule TTP_XOR_QUAD_CurrentVersionRun_3ed9 {
  strings:
    $key_3ed9 = { 6d b6 [2] 49 b8 [2] 62 94 [2] 4c b6 [2] 58 ad [2] 57 b7 [2] 49 aa [2] 4b ab [2] 50 ad [2] 4c aa [2] 50 85 }

  condition:
    any of them
}