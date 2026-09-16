rule TTP_XOR_QUAD_CurrentVersionRun_4c73 {
  strings:
    $key_4c73 = { 1f 1c [2] 3b 12 [2] 10 3e [2] 3e 1c [2] 2a 07 [2] 25 1d [2] 3b 00 [2] 39 01 [2] 22 07 [2] 3e 00 [2] 22 2f }

  condition:
    any of them
}