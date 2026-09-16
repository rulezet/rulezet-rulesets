rule TTP_XOR_QUAD_CurrentVersionRun_1769 {
  strings:
    $key_1769 = { 44 06 [2] 60 08 [2] 4b 24 [2] 65 06 [2] 71 1d [2] 7e 07 [2] 60 1a [2] 62 1b [2] 79 1d [2] 65 1a [2] 79 35 }

  condition:
    any of them
}