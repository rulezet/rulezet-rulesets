rule TTP_XOR_QUAD_CurrentVersionRun_4d77 {
  strings:
    $key_4d77 = { 1e 18 [2] 3a 16 [2] 11 3a [2] 3f 18 [2] 2b 03 [2] 24 19 [2] 3a 04 [2] 38 05 [2] 23 03 [2] 3f 04 [2] 23 2b }

  condition:
    any of them
}