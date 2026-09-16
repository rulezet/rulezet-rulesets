rule TTP_XOR_QUAD_CurrentVersionRun_3663 {
  strings:
    $key_3663 = { 65 0c [2] 41 02 [2] 6a 2e [2] 44 0c [2] 50 17 [2] 5f 0d [2] 41 10 [2] 43 11 [2] 58 17 [2] 44 10 [2] 58 3f }

  condition:
    any of them
}