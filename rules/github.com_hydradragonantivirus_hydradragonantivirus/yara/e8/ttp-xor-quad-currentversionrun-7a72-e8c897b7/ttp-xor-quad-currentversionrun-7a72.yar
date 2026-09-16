rule TTP_XOR_QUAD_CurrentVersionRun_7a72 {
  strings:
    $key_7a72 = { 29 1d [2] 0d 13 [2] 26 3f [2] 08 1d [2] 1c 06 [2] 13 1c [2] 0d 01 [2] 0f 00 [2] 14 06 [2] 08 01 [2] 14 2e }

  condition:
    any of them
}