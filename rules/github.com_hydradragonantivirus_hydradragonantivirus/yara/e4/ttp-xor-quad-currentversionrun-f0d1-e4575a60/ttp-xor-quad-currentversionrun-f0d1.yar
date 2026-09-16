rule TTP_XOR_QUAD_CurrentVersionRun_f0d1 {
  strings:
    $key_f0d1 = { a3 be [2] 87 b0 [2] ac 9c [2] 82 be [2] 96 a5 [2] 99 bf [2] 87 a2 [2] 85 a3 [2] 9e a5 [2] 82 a2 [2] 9e 8d }

  condition:
    any of them
}