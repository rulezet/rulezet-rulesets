rule TTP_XOR_QUAD_CurrentVersionRun_3975 {
  strings:
    $key_3975 = { 6a 1a [2] 4e 14 [2] 65 38 [2] 4b 1a [2] 5f 01 [2] 50 1b [2] 4e 06 [2] 4c 07 [2] 57 01 [2] 4b 06 [2] 57 29 }

  condition:
    any of them
}