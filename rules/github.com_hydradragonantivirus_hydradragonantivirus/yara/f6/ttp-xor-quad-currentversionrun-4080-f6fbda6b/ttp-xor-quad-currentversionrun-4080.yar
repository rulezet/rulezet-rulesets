rule TTP_XOR_QUAD_CurrentVersionRun_4080 {
  strings:
    $key_4080 = { 13 ef [2] 37 e1 [2] 1c cd [2] 32 ef [2] 26 f4 [2] 29 ee [2] 37 f3 [2] 35 f2 [2] 2e f4 [2] 32 f3 [2] 2e dc }

  condition:
    any of them
}