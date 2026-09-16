rule TTP_XOR_QUAD_CurrentVersionRun_2a63 {
  strings:
    $key_2a63 = { 79 0c [2] 5d 02 [2] 76 2e [2] 58 0c [2] 4c 17 [2] 43 0d [2] 5d 10 [2] 5f 11 [2] 44 17 [2] 58 10 [2] 44 3f }

  condition:
    any of them
}