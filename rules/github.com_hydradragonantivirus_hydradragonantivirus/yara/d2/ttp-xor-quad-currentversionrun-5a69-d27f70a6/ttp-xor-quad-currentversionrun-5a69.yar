rule TTP_XOR_QUAD_CurrentVersionRun_5a69 {
  strings:
    $key_5a69 = { 09 06 [2] 2d 08 [2] 06 24 [2] 28 06 [2] 3c 1d [2] 33 07 [2] 2d 1a [2] 2f 1b [2] 34 1d [2] 28 1a [2] 34 35 }

  condition:
    any of them
}