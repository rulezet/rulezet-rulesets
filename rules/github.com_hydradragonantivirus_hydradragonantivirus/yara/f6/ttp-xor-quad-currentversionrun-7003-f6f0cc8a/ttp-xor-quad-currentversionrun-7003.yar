rule TTP_XOR_QUAD_CurrentVersionRun_7003 {
  strings:
    $key_7003 = { 23 6c [2] 07 62 [2] 2c 4e [2] 02 6c [2] 16 77 [2] 19 6d [2] 07 70 [2] 05 71 [2] 1e 77 [2] 02 70 [2] 1e 5f }

  condition:
    any of them
}