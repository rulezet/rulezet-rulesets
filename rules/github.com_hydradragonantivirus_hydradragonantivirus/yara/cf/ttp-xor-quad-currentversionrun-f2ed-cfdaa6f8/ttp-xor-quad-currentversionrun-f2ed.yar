rule TTP_XOR_QUAD_CurrentVersionRun_f2ed {
  strings:
    $key_f2ed = { a1 82 [2] 85 8c [2] ae a0 [2] 80 82 [2] 94 99 [2] 9b 83 [2] 85 9e [2] 87 9f [2] 9c 99 [2] 80 9e [2] 9c b1 }

  condition:
    any of them
}