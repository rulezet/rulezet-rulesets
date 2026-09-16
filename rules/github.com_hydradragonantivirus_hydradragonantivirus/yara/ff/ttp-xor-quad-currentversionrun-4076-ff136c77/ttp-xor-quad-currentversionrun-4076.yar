rule TTP_XOR_QUAD_CurrentVersionRun_4076 {
  strings:
    $key_4076 = { 13 19 [2] 37 17 [2] 1c 3b [2] 32 19 [2] 26 02 [2] 29 18 [2] 37 05 [2] 35 04 [2] 2e 02 [2] 32 05 [2] 2e 2a }

  condition:
    any of them
}