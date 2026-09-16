rule TTP_XOR_QUAD_CurrentVersionRun_2080 {
  strings:
    $key_2080 = { 73 ef [2] 57 e1 [2] 7c cd [2] 52 ef [2] 46 f4 [2] 49 ee [2] 57 f3 [2] 55 f2 [2] 4e f4 [2] 52 f3 [2] 4e dc }

  condition:
    any of them
}