rule TTP_XOR_QUAD_CurrentVersionRun_1e63 {
  strings:
    $key_1e63 = { 4d 0c [2] 69 02 [2] 42 2e [2] 6c 0c [2] 78 17 [2] 77 0d [2] 69 10 [2] 6b 11 [2] 70 17 [2] 6c 10 [2] 70 3f }

  condition:
    any of them
}