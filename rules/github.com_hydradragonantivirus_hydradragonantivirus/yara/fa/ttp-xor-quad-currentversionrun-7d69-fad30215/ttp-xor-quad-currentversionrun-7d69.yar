rule TTP_XOR_QUAD_CurrentVersionRun_7d69 {
  strings:
    $key_7d69 = { 2e 06 [2] 0a 08 [2] 21 24 [2] 0f 06 [2] 1b 1d [2] 14 07 [2] 0a 1a [2] 08 1b [2] 13 1d [2] 0f 1a [2] 13 35 }

  condition:
    any of them
}