rule TTP_XOR_QUAD_CurrentVersionRun_7076 {
  strings:
    $key_7076 = { 23 19 [2] 07 17 [2] 2c 3b [2] 02 19 [2] 16 02 [2] 19 18 [2] 07 05 [2] 05 04 [2] 1e 02 [2] 02 05 [2] 1e 2a }

  condition:
    any of them
}