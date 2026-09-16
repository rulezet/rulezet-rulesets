rule TTP_XOR_QUAD_CurrentVersionRun_46ed {
  strings:
    $key_46ed = { 15 82 [2] 31 8c [2] 1a a0 [2] 34 82 [2] 20 99 [2] 2f 83 [2] 31 9e [2] 33 9f [2] 28 99 [2] 34 9e [2] 28 b1 }

  condition:
    any of them
}