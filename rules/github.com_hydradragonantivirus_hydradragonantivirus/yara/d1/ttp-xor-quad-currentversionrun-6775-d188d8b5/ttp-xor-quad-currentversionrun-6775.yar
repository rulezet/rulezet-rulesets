rule TTP_XOR_QUAD_CurrentVersionRun_6775 {
  strings:
    $key_6775 = { 34 1a [2] 10 14 [2] 3b 38 [2] 15 1a [2] 01 01 [2] 0e 1b [2] 10 06 [2] 12 07 [2] 09 01 [2] 15 06 [2] 09 29 }

  condition:
    any of them
}