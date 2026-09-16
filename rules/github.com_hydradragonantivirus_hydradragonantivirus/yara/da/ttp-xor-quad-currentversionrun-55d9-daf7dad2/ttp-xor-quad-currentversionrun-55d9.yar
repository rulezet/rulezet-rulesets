rule TTP_XOR_QUAD_CurrentVersionRun_55d9 {
  strings:
    $key_55d9 = { 06 b6 [2] 22 b8 [2] 09 94 [2] 27 b6 [2] 33 ad [2] 3c b7 [2] 22 aa [2] 20 ab [2] 3b ad [2] 27 aa [2] 3b 85 }

  condition:
    any of them
}