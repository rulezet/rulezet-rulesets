rule TTP_XOR_QUAD_CurrentVersionRun_4780 {
  strings:
    $key_4780 = { 14 ef [2] 30 e1 [2] 1b cd [2] 35 ef [2] 21 f4 [2] 2e ee [2] 30 f3 [2] 32 f2 [2] 29 f4 [2] 35 f3 [2] 29 dc }

  condition:
    any of them
}