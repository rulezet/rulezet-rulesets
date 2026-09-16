rule TTP_XOR_QUAD_CurrentVersionRun_53e7 {
  strings:
    $key_53e7 = { 00 88 [2] 24 86 [2] 0f aa [2] 21 88 [2] 35 93 [2] 3a 89 [2] 24 94 [2] 26 95 [2] 3d 93 [2] 21 94 [2] 3d bb }

  condition:
    any of them
}