rule TTP_XOR_QUAD_CurrentVersionRun_7c67 {
  strings:
    $key_7c67 = { 2f 08 [2] 0b 06 [2] 20 2a [2] 0e 08 [2] 1a 13 [2] 15 09 [2] 0b 14 [2] 09 15 [2] 12 13 [2] 0e 14 [2] 12 3b }

  condition:
    any of them
}