rule TTP_XOR_QUAD_CurrentVersionRun_6074 {
  strings:
    $key_6074 = { 33 1b [2] 17 15 [2] 3c 39 [2] 12 1b [2] 06 00 [2] 09 1a [2] 17 07 [2] 15 06 [2] 0e 00 [2] 12 07 [2] 0e 28 }

  condition:
    any of them
}