rule TTP_XOR_QUAD_CurrentVersionRun_71c4 {
  strings:
    $key_71c4 = { 22 ab [2] 06 a5 [2] 2d 89 [2] 03 ab [2] 17 b0 [2] 18 aa [2] 06 b7 [2] 04 b6 [2] 1f b0 [2] 03 b7 [2] 1f 98 }

  condition:
    any of them
}