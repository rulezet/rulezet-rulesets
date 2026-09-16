rule TTP_XOR_QUAD_CurrentVersionRun_7d44 {
  strings:
    $key_7d44 = { 2e 2b [2] 0a 25 [2] 21 09 [2] 0f 2b [2] 1b 30 [2] 14 2a [2] 0a 37 [2] 08 36 [2] 13 30 [2] 0f 37 [2] 13 18 }

  condition:
    any of them
}