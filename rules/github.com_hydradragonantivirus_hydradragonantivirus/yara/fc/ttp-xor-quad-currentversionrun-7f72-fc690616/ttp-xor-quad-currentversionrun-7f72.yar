rule TTP_XOR_QUAD_CurrentVersionRun_7f72 {
  strings:
    $key_7f72 = { 2c 1d [2] 08 13 [2] 23 3f [2] 0d 1d [2] 19 06 [2] 16 1c [2] 08 01 [2] 0a 00 [2] 11 06 [2] 0d 01 [2] 11 2e }

  condition:
    any of them
}