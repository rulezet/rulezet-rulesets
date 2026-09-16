rule TTP_XOR_QUAD_CurrentVersionRun_2f77 {
  strings:
    $key_2f77 = { 7c 18 [2] 58 16 [2] 73 3a [2] 5d 18 [2] 49 03 [2] 46 19 [2] 58 04 [2] 5a 05 [2] 41 03 [2] 5d 04 [2] 41 2b }

  condition:
    any of them
}