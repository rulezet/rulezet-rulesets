rule TTP_XOR_QUAD_CurrentVersionRun_5780 {
  strings:
    $key_5780 = { 04 ef [2] 20 e1 [2] 0b cd [2] 25 ef [2] 31 f4 [2] 3e ee [2] 20 f3 [2] 22 f2 [2] 39 f4 [2] 25 f3 [2] 39 dc }

  condition:
    any of them
}