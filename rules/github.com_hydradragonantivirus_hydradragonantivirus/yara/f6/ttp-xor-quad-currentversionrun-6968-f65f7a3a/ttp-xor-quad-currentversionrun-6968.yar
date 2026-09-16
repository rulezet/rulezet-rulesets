rule TTP_XOR_QUAD_CurrentVersionRun_6968 {
  strings:
    $key_6968 = { 3a 07 [2] 1e 09 [2] 35 25 [2] 1b 07 [2] 0f 1c [2] 00 06 [2] 1e 1b [2] 1c 1a [2] 07 1c [2] 1b 1b [2] 07 34 }

  condition:
    any of them
}