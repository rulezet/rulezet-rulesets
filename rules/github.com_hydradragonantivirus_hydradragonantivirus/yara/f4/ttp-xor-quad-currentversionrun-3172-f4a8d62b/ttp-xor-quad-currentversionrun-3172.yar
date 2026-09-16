rule TTP_XOR_QUAD_CurrentVersionRun_3172 {
  strings:
    $key_3172 = { 62 1d [2] 46 13 [2] 6d 3f [2] 43 1d [2] 57 06 [2] 58 1c [2] 46 01 [2] 44 00 [2] 5f 06 [2] 43 01 [2] 5f 2e }

  condition:
    any of them
}