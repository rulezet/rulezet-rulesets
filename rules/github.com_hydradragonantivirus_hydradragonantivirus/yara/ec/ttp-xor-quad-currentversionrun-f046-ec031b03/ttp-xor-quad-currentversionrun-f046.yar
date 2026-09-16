rule TTP_XOR_QUAD_CurrentVersionRun_f046 {
  strings:
    $key_f046 = { a3 29 [2] 87 27 [2] ac 0b [2] 82 29 [2] 96 32 [2] 99 28 [2] 87 35 [2] 85 34 [2] 9e 32 [2] 82 35 [2] 9e 1a }

  condition:
    any of them
}