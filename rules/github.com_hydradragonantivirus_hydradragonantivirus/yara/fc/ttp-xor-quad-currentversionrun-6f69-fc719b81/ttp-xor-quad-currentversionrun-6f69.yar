rule TTP_XOR_QUAD_CurrentVersionRun_6f69 {
  strings:
    $key_6f69 = { 3c 06 [2] 18 08 [2] 33 24 [2] 1d 06 [2] 09 1d [2] 06 07 [2] 18 1a [2] 1a 1b [2] 01 1d [2] 1d 1a [2] 01 35 }

  condition:
    any of them
}