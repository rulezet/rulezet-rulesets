rule TTP_XOR_QUAD_CurrentVersionRun_5a62 {
  strings:
    $key_5a62 = { 09 0d [2] 2d 03 [2] 06 2f [2] 28 0d [2] 3c 16 [2] 33 0c [2] 2d 11 [2] 2f 10 [2] 34 16 [2] 28 11 [2] 34 3e }

  condition:
    any of them
}