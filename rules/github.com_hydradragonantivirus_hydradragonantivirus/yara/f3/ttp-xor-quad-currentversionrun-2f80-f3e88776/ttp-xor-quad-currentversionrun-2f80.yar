rule TTP_XOR_QUAD_CurrentVersionRun_2f80 {
  strings:
    $key_2f80 = { 7c ef [2] 58 e1 [2] 73 cd [2] 5d ef [2] 49 f4 [2] 46 ee [2] 58 f3 [2] 5a f2 [2] 41 f4 [2] 5d f3 [2] 41 dc }

  condition:
    any of them
}