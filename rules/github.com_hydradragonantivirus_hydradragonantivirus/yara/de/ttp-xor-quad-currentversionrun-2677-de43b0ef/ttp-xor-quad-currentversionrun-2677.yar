rule TTP_XOR_QUAD_CurrentVersionRun_2677 {
  strings:
    $key_2677 = { 75 18 [2] 51 16 [2] 7a 3a [2] 54 18 [2] 40 03 [2] 4f 19 [2] 51 04 [2] 53 05 [2] 48 03 [2] 54 04 [2] 48 2b }

  condition:
    any of them
}