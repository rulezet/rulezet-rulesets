rule TTP_XOR_QUAD_CurrentVersionRun_5569 {
  strings:
    $key_5569 = { 06 06 [2] 22 08 [2] 09 24 [2] 27 06 [2] 33 1d [2] 3c 07 [2] 22 1a [2] 20 1b [2] 3b 1d [2] 27 1a [2] 3b 35 }

  condition:
    any of them
}