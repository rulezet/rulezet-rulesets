rule TTP_XOR_QUAD_CurrentVersionRun_4e72 {
  strings:
    $key_4e72 = { 1d 1d [2] 39 13 [2] 12 3f [2] 3c 1d [2] 28 06 [2] 27 1c [2] 39 01 [2] 3b 00 [2] 20 06 [2] 3c 01 [2] 20 2e }

  condition:
    any of them
}