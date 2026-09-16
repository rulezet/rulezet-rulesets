rule TTP_XOR_QUAD_CurrentVersionRun_7780 {
  strings:
    $key_7780 = { 24 ef [2] 00 e1 [2] 2b cd [2] 05 ef [2] 11 f4 [2] 1e ee [2] 00 f3 [2] 02 f2 [2] 19 f4 [2] 05 f3 [2] 19 dc }

  condition:
    any of them
}