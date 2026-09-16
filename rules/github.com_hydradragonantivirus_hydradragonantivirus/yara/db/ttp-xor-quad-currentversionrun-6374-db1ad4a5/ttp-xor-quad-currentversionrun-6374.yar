rule TTP_XOR_QUAD_CurrentVersionRun_6374 {
  strings:
    $key_6374 = { 30 1b [2] 14 15 [2] 3f 39 [2] 11 1b [2] 05 00 [2] 0a 1a [2] 14 07 [2] 16 06 [2] 0d 00 [2] 11 07 [2] 0d 28 }

  condition:
    any of them
}