rule TTP_XOR_QUAD_CurrentVersionRun_6975 {
  strings:
    $key_6975 = { 3a 1a [2] 1e 14 [2] 35 38 [2] 1b 1a [2] 0f 01 [2] 00 1b [2] 1e 06 [2] 1c 07 [2] 07 01 [2] 1b 06 [2] 07 29 }

  condition:
    any of them
}