rule TTP_XOR_QUAD_CurrentVersionRun_4067 {
  strings:
    $key_4067 = { 13 08 [2] 37 06 [2] 1c 2a [2] 32 08 [2] 26 13 [2] 29 09 [2] 37 14 [2] 35 15 [2] 2e 13 [2] 32 14 [2] 2e 3b }

  condition:
    any of them
}