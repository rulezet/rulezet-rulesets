rule TTP_XOR_QUAD_CurrentVersionRun_7d75 {
  strings:
    $key_7d75 = { 2e 1a [2] 0a 14 [2] 21 38 [2] 0f 1a [2] 1b 01 [2] 14 1b [2] 0a 06 [2] 08 07 [2] 13 01 [2] 0f 06 [2] 13 29 }

  condition:
    any of them
}