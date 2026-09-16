rule TTP_XOR_QUAD_CurrentVersionRun_1767 {
  strings:
    $key_1767 = { 44 08 [2] 60 06 [2] 4b 2a [2] 65 08 [2] 71 13 [2] 7e 09 [2] 60 14 [2] 62 15 [2] 79 13 [2] 65 14 [2] 79 3b }

  condition:
    any of them
}