rule TTP_XOR_QUAD_CurrentVersionRun_71d9 {
  strings:
    $key_71d9 = { 22 b6 [2] 06 b8 [2] 2d 94 [2] 03 b6 [2] 17 ad [2] 18 b7 [2] 06 aa [2] 04 ab [2] 1f ad [2] 03 aa [2] 1f 85 }

  condition:
    any of them
}