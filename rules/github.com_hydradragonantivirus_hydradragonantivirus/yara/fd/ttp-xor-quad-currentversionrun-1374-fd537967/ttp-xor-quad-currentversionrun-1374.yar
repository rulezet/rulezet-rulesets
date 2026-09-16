rule TTP_XOR_QUAD_CurrentVersionRun_1374 {
  strings:
    $key_1374 = { 40 1b [2] 64 15 [2] 4f 39 [2] 61 1b [2] 75 00 [2] 7a 1a [2] 64 07 [2] 66 06 [2] 7d 00 [2] 61 07 [2] 7d 28 }

  condition:
    any of them
}