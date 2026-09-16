rule TTP_XOR_QUAD_CurrentVersionRun_7269 {
  strings:
    $key_7269 = { 21 06 [2] 05 08 [2] 2e 24 [2] 00 06 [2] 14 1d [2] 1b 07 [2] 05 1a [2] 07 1b [2] 1c 1d [2] 00 1a [2] 1c 35 }

  condition:
    any of them
}