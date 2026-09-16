rule TTP_XOR_QUAD_CurrentVersionRun_f063 {
  strings:
    $key_f063 = { a3 0c [2] 87 02 [2] ac 2e [2] 82 0c [2] 96 17 [2] 99 0d [2] 87 10 [2] 85 11 [2] 9e 17 [2] 82 10 [2] 9e 3f }

  condition:
    any of them
}