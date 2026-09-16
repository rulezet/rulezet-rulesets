rule TTP_XOR_QUAD_CurrentVersionRun_76d9 {
  strings:
    $key_76d9 = { 25 b6 [2] 01 b8 [2] 2a 94 [2] 04 b6 [2] 10 ad [2] 1f b7 [2] 01 aa [2] 03 ab [2] 18 ad [2] 04 aa [2] 18 85 }

  condition:
    any of them
}