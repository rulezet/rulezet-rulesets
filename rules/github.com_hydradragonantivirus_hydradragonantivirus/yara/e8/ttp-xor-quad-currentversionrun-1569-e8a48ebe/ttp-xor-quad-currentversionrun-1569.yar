rule TTP_XOR_QUAD_CurrentVersionRun_1569 {
  strings:
    $key_1569 = { 46 06 [2] 62 08 [2] 49 24 [2] 67 06 [2] 73 1d [2] 7c 07 [2] 62 1a [2] 60 1b [2] 7b 1d [2] 67 1a [2] 7b 35 }

  condition:
    any of them
}