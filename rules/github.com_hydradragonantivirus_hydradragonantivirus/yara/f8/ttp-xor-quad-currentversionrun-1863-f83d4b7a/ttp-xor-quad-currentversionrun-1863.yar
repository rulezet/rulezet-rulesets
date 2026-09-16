rule TTP_XOR_QUAD_CurrentVersionRun_1863 {
  strings:
    $key_1863 = { 4b 0c [2] 6f 02 [2] 44 2e [2] 6a 0c [2] 7e 17 [2] 71 0d [2] 6f 10 [2] 6d 11 [2] 76 17 [2] 6a 10 [2] 76 3f }

  condition:
    any of them
}