rule TTP_XOR_QUAD_CurrentVersionRun_6c75 {
  strings:
    $key_6c75 = { 3f 1a [2] 1b 14 [2] 30 38 [2] 1e 1a [2] 0a 01 [2] 05 1b [2] 1b 06 [2] 19 07 [2] 02 01 [2] 1e 06 [2] 02 29 }

  condition:
    any of them
}