rule TTP_XOR_QUAD_CurrentVersionRun_de94 {
  strings:
    $key_de94 = { 8d fb [2] a9 f5 [2] 82 d9 [2] ac fb [2] b8 e0 [2] b7 fa [2] a9 e7 [2] ab e6 [2] b0 e0 [2] ac e7 [2] b0 c8 }

  condition:
    any of them
}