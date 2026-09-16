rule TTP_XOR_QUAD_CurrentVersionRun_1877 {
  strings:
    $key_1877 = { 4b 18 [2] 6f 16 [2] 44 3a [2] 6a 18 [2] 7e 03 [2] 71 19 [2] 6f 04 [2] 6d 05 [2] 76 03 [2] 6a 04 [2] 76 2b }

  condition:
    any of them
}