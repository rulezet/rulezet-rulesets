rule TTP_XOR_QUAD_CurrentVersionRun_6323 {
  strings:
    $key_6323 = { 30 4c [2] 14 42 [2] 3f 6e [2] 11 4c [2] 05 57 [2] 0a 4d [2] 14 50 [2] 16 51 [2] 0d 57 [2] 11 50 [2] 0d 7f }

  condition:
    any of them
}