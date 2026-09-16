rule TTP_XOR_QUAD_CurrentVersionRun_56d9 {
  strings:
    $key_56d9 = { 05 b6 [2] 21 b8 [2] 0a 94 [2] 24 b6 [2] 30 ad [2] 3f b7 [2] 21 aa [2] 23 ab [2] 38 ad [2] 24 aa [2] 38 85 }

  condition:
    any of them
}