rule TTP_XOR_QUAD_CurrentVersionRun_7b73 {
  strings:
    $key_7b73 = { 28 1c [2] 0c 12 [2] 27 3e [2] 09 1c [2] 1d 07 [2] 12 1d [2] 0c 00 [2] 0e 01 [2] 15 07 [2] 09 00 [2] 15 2f }

  condition:
    any of them
}