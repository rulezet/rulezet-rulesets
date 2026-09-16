rule TTP_XOR_QUAD_CurrentVersionRun_f7ed {
  strings:
    $key_f7ed = { a4 82 [2] 80 8c [2] ab a0 [2] 85 82 [2] 91 99 [2] 9e 83 [2] 80 9e [2] 82 9f [2] 99 99 [2] 85 9e [2] 99 b1 }

  condition:
    any of them
}