rule TTP_XOR_QUAD_CurrentVersionRun_7f76 {
  strings:
    $key_7f76 = { 2c 19 [2] 08 17 [2] 23 3b [2] 0d 19 [2] 19 02 [2] 16 18 [2] 08 05 [2] 0a 04 [2] 11 02 [2] 0d 05 [2] 11 2a }

  condition:
    any of them
}