rule TTP_XOR_QUAD_CurrentVersionRun_7067 {
  strings:
    $key_7067 = { 23 08 [2] 07 06 [2] 2c 2a [2] 02 08 [2] 16 13 [2] 19 09 [2] 07 14 [2] 05 15 [2] 1e 13 [2] 02 14 [2] 1e 3b }

  condition:
    any of them
}