rule TTP_XOR_QUAD_CurrentVersionRun_6880 {
  strings:
    $key_6880 = { 3b ef [2] 1f e1 [2] 34 cd [2] 1a ef [2] 0e f4 [2] 01 ee [2] 1f f3 [2] 1d f2 [2] 06 f4 [2] 1a f3 [2] 06 dc }

  condition:
    any of them
}