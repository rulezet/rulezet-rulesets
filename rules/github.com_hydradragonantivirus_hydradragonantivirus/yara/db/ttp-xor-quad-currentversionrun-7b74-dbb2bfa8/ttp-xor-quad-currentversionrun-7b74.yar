rule TTP_XOR_QUAD_CurrentVersionRun_7b74 {
  strings:
    $key_7b74 = { 28 1b [2] 0c 15 [2] 27 39 [2] 09 1b [2] 1d 00 [2] 12 1a [2] 0c 07 [2] 0e 06 [2] 15 00 [2] 09 07 [2] 15 28 }

  condition:
    any of them
}