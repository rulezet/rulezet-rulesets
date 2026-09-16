rule TTP_XOR_QUAD_CurrentVersionRun_5fd9 {
  strings:
    $key_5fd9 = { 0c b6 [2] 28 b8 [2] 03 94 [2] 2d b6 [2] 39 ad [2] 36 b7 [2] 28 aa [2] 2a ab [2] 31 ad [2] 2d aa [2] 31 85 }

  condition:
    any of them
}