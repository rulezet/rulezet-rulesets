rule TTP_XOR_QUAD_CurrentVersionRun_2475 {
  strings:
    $key_2475 = { 77 1a [2] 53 14 [2] 78 38 [2] 56 1a [2] 42 01 [2] 4d 1b [2] 53 06 [2] 51 07 [2] 4a 01 [2] 56 06 [2] 4a 29 }

  condition:
    any of them
}