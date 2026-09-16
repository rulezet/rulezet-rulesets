rule TTP_XOR_QUAD_CurrentVersionRun_57ed {
  strings:
    $key_57ed = { 04 82 [2] 20 8c [2] 0b a0 [2] 25 82 [2] 31 99 [2] 3e 83 [2] 20 9e [2] 22 9f [2] 39 99 [2] 25 9e [2] 39 b1 }

  condition:
    any of them
}