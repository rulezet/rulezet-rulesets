rule TTP_XOR_QUAD_CurrentVersionRun_4967 {
  strings:
    $key_4967 = { 1a 08 [2] 3e 06 [2] 15 2a [2] 3b 08 [2] 2f 13 [2] 20 09 [2] 3e 14 [2] 3c 15 [2] 27 13 [2] 3b 14 [2] 27 3b }

  condition:
    any of them
}