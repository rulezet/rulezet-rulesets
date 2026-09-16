rule TTP_XOR_QUAD_CurrentVersionRun_4c74 {
  strings:
    $key_4c74 = { 1f 1b [2] 3b 15 [2] 10 39 [2] 3e 1b [2] 2a 00 [2] 25 1a [2] 3b 07 [2] 39 06 [2] 22 00 [2] 3e 07 [2] 22 28 }

  condition:
    any of them
}