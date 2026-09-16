rule TTP_XOR_QUAD_CurrentVersionRun_31c4 {
  strings:
    $key_31c4 = { 62 ab [2] 46 a5 [2] 6d 89 [2] 43 ab [2] 57 b0 [2] 58 aa [2] 46 b7 [2] 44 b6 [2] 5f b0 [2] 43 b7 [2] 5f 98 }

  condition:
    any of them
}