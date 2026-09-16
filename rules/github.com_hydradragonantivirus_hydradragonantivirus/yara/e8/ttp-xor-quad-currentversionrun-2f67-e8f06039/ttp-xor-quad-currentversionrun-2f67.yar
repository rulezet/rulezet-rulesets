rule TTP_XOR_QUAD_CurrentVersionRun_2f67 {
  strings:
    $key_2f67 = { 7c 08 [2] 58 06 [2] 73 2a [2] 5d 08 [2] 49 13 [2] 46 09 [2] 58 14 [2] 5a 15 [2] 41 13 [2] 5d 14 [2] 41 3b }

  condition:
    any of them
}