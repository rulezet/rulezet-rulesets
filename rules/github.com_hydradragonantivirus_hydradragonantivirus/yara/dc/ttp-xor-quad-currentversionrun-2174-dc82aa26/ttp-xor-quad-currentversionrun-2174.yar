rule TTP_XOR_QUAD_CurrentVersionRun_2174 {
  strings:
    $key_2174 = { 72 1b [2] 56 15 [2] 7d 39 [2] 53 1b [2] 47 00 [2] 48 1a [2] 56 07 [2] 54 06 [2] 4f 00 [2] 53 07 [2] 4f 28 }

  condition:
    any of them
}