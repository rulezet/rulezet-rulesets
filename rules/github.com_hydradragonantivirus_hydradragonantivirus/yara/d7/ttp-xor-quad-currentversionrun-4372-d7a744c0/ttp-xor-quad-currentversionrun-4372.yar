rule TTP_XOR_QUAD_CurrentVersionRun_4372 {
  strings:
    $key_4372 = { 10 1d [2] 34 13 [2] 1f 3f [2] 31 1d [2] 25 06 [2] 2a 1c [2] 34 01 [2] 36 00 [2] 2d 06 [2] 31 01 [2] 2d 2e }

  condition:
    any of them
}