rule TTP_XOR_QUAD_CurrentVersionRun_7973 {
  strings:
    $key_7973 = { 2a 1c [2] 0e 12 [2] 25 3e [2] 0b 1c [2] 1f 07 [2] 10 1d [2] 0e 00 [2] 0c 01 [2] 17 07 [2] 0b 00 [2] 17 2f }

  condition:
    any of them
}