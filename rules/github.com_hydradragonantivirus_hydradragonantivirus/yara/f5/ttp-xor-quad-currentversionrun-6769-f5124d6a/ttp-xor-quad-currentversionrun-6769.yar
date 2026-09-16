rule TTP_XOR_QUAD_CurrentVersionRun_6769 {
  strings:
    $key_6769 = { 34 06 [2] 10 08 [2] 3b 24 [2] 15 06 [2] 01 1d [2] 0e 07 [2] 10 1a [2] 12 1b [2] 09 1d [2] 15 1a [2] 09 35 }

  condition:
    any of them
}