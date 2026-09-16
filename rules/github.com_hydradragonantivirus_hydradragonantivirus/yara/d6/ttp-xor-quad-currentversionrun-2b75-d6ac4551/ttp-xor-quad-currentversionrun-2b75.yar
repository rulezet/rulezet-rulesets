rule TTP_XOR_QUAD_CurrentVersionRun_2b75 {
  strings:
    $key_2b75 = { 78 1a [2] 5c 14 [2] 77 38 [2] 59 1a [2] 4d 01 [2] 42 1b [2] 5c 06 [2] 5e 07 [2] 45 01 [2] 59 06 [2] 45 29 }

  condition:
    any of them
}