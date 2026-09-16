rule TTP_XOR_QUAD_CurrentVersionRun_6723 {
  strings:
    $key_6723 = { 34 4c [2] 10 42 [2] 3b 6e [2] 15 4c [2] 01 57 [2] 0e 4d [2] 10 50 [2] 12 51 [2] 09 57 [2] 15 50 [2] 09 7f }

  condition:
    any of them
}