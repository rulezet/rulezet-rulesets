rule TTP_XOR_QUAD_CurrentVersionRun_2a72 {
  strings:
    $key_2a72 = { 79 1d [2] 5d 13 [2] 76 3f [2] 58 1d [2] 4c 06 [2] 43 1c [2] 5d 01 [2] 5f 00 [2] 44 06 [2] 58 01 [2] 44 2e }

  condition:
    any of them
}