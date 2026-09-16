rule TTP_XOR_QUAD_CurrentVersionRun_5272 {
  strings:
    $key_5272 = { 01 1d [2] 25 13 [2] 0e 3f [2] 20 1d [2] 34 06 [2] 3b 1c [2] 25 01 [2] 27 00 [2] 3c 06 [2] 20 01 [2] 3c 2e }

  condition:
    any of them
}