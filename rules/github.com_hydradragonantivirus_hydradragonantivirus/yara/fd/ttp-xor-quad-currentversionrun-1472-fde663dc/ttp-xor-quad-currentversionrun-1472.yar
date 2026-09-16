rule TTP_XOR_QUAD_CurrentVersionRun_1472 {
  strings:
    $key_1472 = { 47 1d [2] 63 13 [2] 48 3f [2] 66 1d [2] 72 06 [2] 7d 1c [2] 63 01 [2] 61 00 [2] 7a 06 [2] 66 01 [2] 7a 2e }

  condition:
    any of them
}