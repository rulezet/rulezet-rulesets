rule TTP_XOR_QUAD_CurrentVersionRun_1780 {
  strings:
    $key_1780 = { 44 ef [2] 60 e1 [2] 4b cd [2] 65 ef [2] 71 f4 [2] 7e ee [2] 60 f3 [2] 62 f2 [2] 79 f4 [2] 65 f3 [2] 79 dc }

  condition:
    any of them
}