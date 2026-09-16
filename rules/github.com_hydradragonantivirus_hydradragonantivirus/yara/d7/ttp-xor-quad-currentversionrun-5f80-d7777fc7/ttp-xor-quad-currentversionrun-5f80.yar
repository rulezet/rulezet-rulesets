rule TTP_XOR_QUAD_CurrentVersionRun_5f80 {
  strings:
    $key_5f80 = { 0c ef [2] 28 e1 [2] 03 cd [2] 2d ef [2] 39 f4 [2] 36 ee [2] 28 f3 [2] 2a f2 [2] 31 f4 [2] 2d f3 [2] 31 dc }

  condition:
    any of them
}