rule TTP_XOR_QUAD_CurrentVersionRun_2374 {
  strings:
    $key_2374 = { 70 1b [2] 54 15 [2] 7f 39 [2] 51 1b [2] 45 00 [2] 4a 1a [2] 54 07 [2] 56 06 [2] 4d 00 [2] 51 07 [2] 4d 28 }

  condition:
    any of them
}