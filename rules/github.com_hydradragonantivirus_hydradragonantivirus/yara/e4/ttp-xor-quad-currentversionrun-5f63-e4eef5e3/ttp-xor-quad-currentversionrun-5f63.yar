rule TTP_XOR_QUAD_CurrentVersionRun_5f63 {
  strings:
    $key_5f63 = { 0c 0c [2] 28 02 [2] 03 2e [2] 2d 0c [2] 39 17 [2] 36 0d [2] 28 10 [2] 2a 11 [2] 31 17 [2] 2d 10 [2] 31 3f }

  condition:
    any of them
}