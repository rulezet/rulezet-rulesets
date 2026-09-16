rule TTP_XOR_QUAD_CurrentVersionRun_1880 {
  strings:
    $key_1880 = { 4b ef [2] 6f e1 [2] 44 cd [2] 6a ef [2] 7e f4 [2] 71 ee [2] 6f f3 [2] 6d f2 [2] 76 f4 [2] 6a f3 [2] 76 dc }

  condition:
    any of them
}