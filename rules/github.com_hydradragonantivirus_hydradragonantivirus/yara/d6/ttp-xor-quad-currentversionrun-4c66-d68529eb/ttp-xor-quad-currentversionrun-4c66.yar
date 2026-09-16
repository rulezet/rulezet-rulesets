rule TTP_XOR_QUAD_CurrentVersionRun_4c66 {
  strings:
    $key_4c66 = { 1f 09 [2] 3b 07 [2] 10 2b [2] 3e 09 [2] 2a 12 [2] 25 08 [2] 3b 15 [2] 39 14 [2] 22 12 [2] 3e 15 [2] 22 3a }

  condition:
    any of them
}