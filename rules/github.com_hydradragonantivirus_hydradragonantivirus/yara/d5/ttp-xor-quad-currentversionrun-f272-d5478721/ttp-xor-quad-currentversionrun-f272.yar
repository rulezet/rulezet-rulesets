rule TTP_XOR_QUAD_CurrentVersionRun_f272 {
  strings:
    $key_f272 = { a1 1d [2] 85 13 [2] ae 3f [2] 80 1d [2] 94 06 [2] 9b 1c [2] 85 01 [2] 87 00 [2] 9c 06 [2] 80 01 [2] 9c 2e }

  condition:
    any of them
}