rule TTP_XOR_QUAD_CurrentVersionRun_f080 {
  strings:
    $key_f080 = { a3 ef [2] 87 e1 [2] ac cd [2] 82 ef [2] 96 f4 [2] 99 ee [2] 87 f3 [2] 85 f2 [2] 9e f4 [2] 82 f3 [2] 9e dc }

  condition:
    any of them
}