rule TTP_XOR_QUAD_CurrentVersionRun_5968 {
  strings:
    $key_5968 = { 0a 07 [2] 2e 09 [2] 05 25 [2] 2b 07 [2] 3f 1c [2] 30 06 [2] 2e 1b [2] 2c 1a [2] 37 1c [2] 2b 1b [2] 37 34 }

  condition:
    any of them
}