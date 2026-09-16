rule TTP_XOR_QUAD_CurrentVersionRun_67ed {
  strings:
    $key_67ed = { 34 82 [2] 10 8c [2] 3b a0 [2] 15 82 [2] 01 99 [2] 0e 83 [2] 10 9e [2] 12 9f [2] 09 99 [2] 15 9e [2] 09 b1 }

  condition:
    any of them
}