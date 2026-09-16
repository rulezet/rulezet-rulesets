rule TTP_XOR_QUAD_CurrentVersionRun_f263 {
  strings:
    $key_f263 = { a1 0c [2] 85 02 [2] ae 2e [2] 80 0c [2] 94 17 [2] 9b 0d [2] 85 10 [2] 87 11 [2] 9c 17 [2] 80 10 [2] 9c 3f }

  condition:
    any of them
}