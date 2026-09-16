rule TTP_XOR_QUAD_CurrentVersionRun_2d67 {
  strings:
    $key_2d67 = { 7e 08 [2] 5a 06 [2] 71 2a [2] 5f 08 [2] 4b 13 [2] 44 09 [2] 5a 14 [2] 58 15 [2] 43 13 [2] 5f 14 [2] 43 3b }

  condition:
    any of them
}