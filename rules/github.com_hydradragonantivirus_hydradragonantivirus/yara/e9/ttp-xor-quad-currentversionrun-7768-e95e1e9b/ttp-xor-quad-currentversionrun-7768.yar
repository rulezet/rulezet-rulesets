rule TTP_XOR_QUAD_CurrentVersionRun_7768 {
  strings:
    $key_7768 = { 24 07 [2] 00 09 [2] 2b 25 [2] 05 07 [2] 11 1c [2] 1e 06 [2] 00 1b [2] 02 1a [2] 19 1c [2] 05 1b [2] 19 34 }

  condition:
    any of them
}