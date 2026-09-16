rule TTP_XOR_QUAD_CurrentVersionRun_fa80 {
  strings:
    $key_fa80 = { a9 ef [2] 8d e1 [2] a6 cd [2] 88 ef [2] 9c f4 [2] 93 ee [2] 8d f3 [2] 8f f2 [2] 94 f4 [2] 88 f3 [2] 94 dc }

  condition:
    any of them
}