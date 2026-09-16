rule TTP_XOR_QUAD_CurrentVersionRun_6974 {
  strings:
    $key_6974 = { 3a 1b [2] 1e 15 [2] 35 39 [2] 1b 1b [2] 0f 00 [2] 00 1a [2] 1e 07 [2] 1c 06 [2] 07 00 [2] 1b 07 [2] 07 28 }

  condition:
    any of them
}