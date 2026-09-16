rule TTP_XOR_QUAD_CurrentVersionRun_41c4 {
  strings:
    $key_41c4 = { 12 ab [2] 36 a5 [2] 1d 89 [2] 33 ab [2] 27 b0 [2] 28 aa [2] 36 b7 [2] 34 b6 [2] 2f b0 [2] 33 b7 [2] 2f 98 }

  condition:
    any of them
}