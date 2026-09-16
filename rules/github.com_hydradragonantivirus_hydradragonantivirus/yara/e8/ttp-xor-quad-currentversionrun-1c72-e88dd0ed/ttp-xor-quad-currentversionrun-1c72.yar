rule TTP_XOR_QUAD_CurrentVersionRun_1c72 {
  strings:
    $key_1c72 = { 4f 1d [2] 6b 13 [2] 40 3f [2] 6e 1d [2] 7a 06 [2] 75 1c [2] 6b 01 [2] 69 00 [2] 72 06 [2] 6e 01 [2] 72 2e }

  condition:
    any of them
}