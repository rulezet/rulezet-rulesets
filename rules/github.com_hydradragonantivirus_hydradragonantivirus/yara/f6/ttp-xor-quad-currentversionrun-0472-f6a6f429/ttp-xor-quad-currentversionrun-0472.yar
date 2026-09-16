rule TTP_XOR_QUAD_CurrentVersionRun_0472 {
  strings:
    $key_0472 = { 57 1d [2] 73 13 [2] 58 3f [2] 76 1d [2] 62 06 [2] 6d 1c [2] 73 01 [2] 71 00 [2] 6a 06 [2] 76 01 [2] 6a 2e }

  condition:
    any of them
}