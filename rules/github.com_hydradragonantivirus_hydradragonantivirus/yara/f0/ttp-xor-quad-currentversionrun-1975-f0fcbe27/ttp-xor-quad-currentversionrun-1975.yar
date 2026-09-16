rule TTP_XOR_QUAD_CurrentVersionRun_1975 {
  strings:
    $key_1975 = { 4a 1a [2] 6e 14 [2] 45 38 [2] 6b 1a [2] 7f 01 [2] 70 1b [2] 6e 06 [2] 6c 07 [2] 77 01 [2] 6b 06 [2] 77 29 }

  condition:
    any of them
}