rule TTP_XOR_QUAD_CurrentVersionRun_7245 {
  strings:
    $key_7245 = { 21 2a [2] 05 24 [2] 2e 08 [2] 00 2a [2] 14 31 [2] 1b 2b [2] 05 36 [2] 07 37 [2] 1c 31 [2] 00 36 [2] 1c 19 }

  condition:
    any of them
}