rule TTP_XOR_QUAD_CurrentVersionRun_0272 {
  strings:
    $key_0272 = { 51 1d [2] 75 13 [2] 5e 3f [2] 70 1d [2] 64 06 [2] 6b 1c [2] 75 01 [2] 77 00 [2] 6c 06 [2] 70 01 [2] 6c 2e }

  condition:
    any of them
}