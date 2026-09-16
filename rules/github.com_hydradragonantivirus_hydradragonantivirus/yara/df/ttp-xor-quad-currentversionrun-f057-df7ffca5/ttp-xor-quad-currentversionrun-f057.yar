rule TTP_XOR_QUAD_CurrentVersionRun_f057 {
  strings:
    $key_f057 = { a3 38 [2] 87 36 [2] ac 1a [2] 82 38 [2] 96 23 [2] 99 39 [2] 87 24 [2] 85 25 [2] 9e 23 [2] 82 24 [2] 9e 0b }

  condition:
    any of them
}