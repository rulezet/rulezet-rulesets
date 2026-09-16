rule TTP_XOR_QUAD_CurrentVersionRun_6c69 {
  strings:
    $key_6c69 = { 3f 06 [2] 1b 08 [2] 30 24 [2] 1e 06 [2] 0a 1d [2] 05 07 [2] 1b 1a [2] 19 1b [2] 02 1d [2] 1e 1a [2] 02 35 }

  condition:
    any of them
}