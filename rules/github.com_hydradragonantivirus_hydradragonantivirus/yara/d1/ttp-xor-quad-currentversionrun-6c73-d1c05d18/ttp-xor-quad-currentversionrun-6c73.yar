rule TTP_XOR_QUAD_CurrentVersionRun_6c73 {
  strings:
    $key_6c73 = { 3f 1c [2] 1b 12 [2] 30 3e [2] 1e 1c [2] 0a 07 [2] 05 1d [2] 1b 00 [2] 19 01 [2] 02 07 [2] 1e 00 [2] 02 2f }

  condition:
    any of them
}