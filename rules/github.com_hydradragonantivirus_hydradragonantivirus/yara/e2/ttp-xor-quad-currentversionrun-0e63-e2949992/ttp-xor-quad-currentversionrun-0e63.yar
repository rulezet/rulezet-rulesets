rule TTP_XOR_QUAD_CurrentVersionRun_0e63 {
  strings:
    $key_0e63 = { 5d 0c [2] 79 02 [2] 52 2e [2] 7c 0c [2] 68 17 [2] 67 0d [2] 79 10 [2] 7b 11 [2] 60 17 [2] 7c 10 [2] 60 3f }

  condition:
    any of them
}