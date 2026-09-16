rule TTP_XOR_QUAD_CurrentVersionRun_1f23 {
  strings:
    $key_1f23 = { 4c 4c [2] 68 42 [2] 43 6e [2] 6d 4c [2] 79 57 [2] 76 4d [2] 68 50 [2] 6a 51 [2] 71 57 [2] 6d 50 [2] 71 7f }

  condition:
    any of them
}