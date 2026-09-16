rule TTP_XOR_QUAD_CurrentVersionRun_f072 {
  strings:
    $key_f072 = { a3 1d [2] 87 13 [2] ac 3f [2] 82 1d [2] 96 06 [2] 99 1c [2] 87 01 [2] 85 00 [2] 9e 06 [2] 82 01 [2] 9e 2e }

  condition:
    any of them
}