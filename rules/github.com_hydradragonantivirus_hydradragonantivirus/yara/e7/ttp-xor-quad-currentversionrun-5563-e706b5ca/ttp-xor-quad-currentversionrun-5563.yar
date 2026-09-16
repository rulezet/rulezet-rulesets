rule TTP_XOR_QUAD_CurrentVersionRun_5563 {
  strings:
    $key_5563 = { 06 0c [2] 22 02 [2] 09 2e [2] 27 0c [2] 33 17 [2] 3c 0d [2] 22 10 [2] 20 11 [2] 3b 17 [2] 27 10 [2] 3b 3f }

  condition:
    any of them
}