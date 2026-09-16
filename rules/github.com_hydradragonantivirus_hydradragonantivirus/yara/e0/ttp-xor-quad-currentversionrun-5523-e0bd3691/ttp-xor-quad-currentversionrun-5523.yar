rule TTP_XOR_QUAD_CurrentVersionRun_5523 {
  strings:
    $key_5523 = { 06 4c [2] 22 42 [2] 09 6e [2] 27 4c [2] 33 57 [2] 3c 4d [2] 22 50 [2] 20 51 [2] 3b 57 [2] 27 50 [2] 3b 7f }

  condition:
    any of them
}