rule TTP_XOR_QUAD_CurrentVersionRun_3880 {
  strings:
    $key_3880 = { 6b ef [2] 4f e1 [2] 64 cd [2] 4a ef [2] 5e f4 [2] 51 ee [2] 4f f3 [2] 4d f2 [2] 56 f4 [2] 4a f3 [2] 56 dc }

  condition:
    any of them
}