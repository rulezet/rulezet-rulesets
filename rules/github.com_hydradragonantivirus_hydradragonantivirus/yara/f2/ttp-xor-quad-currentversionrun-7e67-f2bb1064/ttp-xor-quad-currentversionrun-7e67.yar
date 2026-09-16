rule TTP_XOR_QUAD_CurrentVersionRun_7e67 {
  strings:
    $key_7e67 = { 2d 08 [2] 09 06 [2] 22 2a [2] 0c 08 [2] 18 13 [2] 17 09 [2] 09 14 [2] 0b 15 [2] 10 13 [2] 0c 14 [2] 10 3b }

  condition:
    any of them
}