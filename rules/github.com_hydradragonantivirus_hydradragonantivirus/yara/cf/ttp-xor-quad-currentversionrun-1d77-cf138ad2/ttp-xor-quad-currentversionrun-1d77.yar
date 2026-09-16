rule TTP_XOR_QUAD_CurrentVersionRun_1d77 {
  strings:
    $key_1d77 = { 4e 18 [2] 6a 16 [2] 41 3a [2] 6f 18 [2] 7b 03 [2] 74 19 [2] 6a 04 [2] 68 05 [2] 73 03 [2] 6f 04 [2] 73 2b }

  condition:
    any of them
}