rule TTP_XOR_QUAD_CurrentVersionRun_5f23 {
  strings:
    $key_5f23 = { 0c 4c [2] 28 42 [2] 03 6e [2] 2d 4c [2] 39 57 [2] 36 4d [2] 28 50 [2] 2a 51 [2] 31 57 [2] 2d 50 [2] 31 7f }

  condition:
    any of them
}