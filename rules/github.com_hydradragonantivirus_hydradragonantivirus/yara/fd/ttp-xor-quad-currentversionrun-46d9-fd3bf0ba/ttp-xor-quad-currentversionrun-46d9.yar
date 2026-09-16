rule TTP_XOR_QUAD_CurrentVersionRun_46d9 {
  strings:
    $key_46d9 = { 15 b6 [2] 31 b8 [2] 1a 94 [2] 34 b6 [2] 20 ad [2] 2f b7 [2] 31 aa [2] 33 ab [2] 28 ad [2] 34 aa [2] 28 85 }

  condition:
    any of them
}