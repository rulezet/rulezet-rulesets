rule TTP_XOR_QUAD_CurrentVersionRun_3977 {
  strings:
    $key_3977 = { 6a 18 [2] 4e 16 [2] 65 3a [2] 4b 18 [2] 5f 03 [2] 50 19 [2] 4e 04 [2] 4c 05 [2] 57 03 [2] 4b 04 [2] 57 2b }

  condition:
    any of them
}