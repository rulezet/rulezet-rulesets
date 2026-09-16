rule TTP_XOR_QUAD_CurrentVersionRun_6474 {
  strings:
    $key_6474 = { 37 1b [2] 13 15 [2] 38 39 [2] 16 1b [2] 02 00 [2] 0d 1a [2] 13 07 [2] 11 06 [2] 0a 00 [2] 16 07 [2] 0a 28 }

  condition:
    any of them
}