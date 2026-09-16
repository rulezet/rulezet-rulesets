rule TTP_XOR_QUAD_CurrentVersionRun_7b63 {
  strings:
    $key_7b63 = { 28 0c [2] 0c 02 [2] 27 2e [2] 09 0c [2] 1d 17 [2] 12 0d [2] 0c 10 [2] 0e 11 [2] 15 17 [2] 09 10 [2] 15 3f }

  condition:
    any of them
}