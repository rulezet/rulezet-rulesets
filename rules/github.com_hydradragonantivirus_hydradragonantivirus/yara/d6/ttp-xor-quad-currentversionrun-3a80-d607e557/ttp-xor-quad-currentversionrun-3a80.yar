rule TTP_XOR_QUAD_CurrentVersionRun_3a80 {
  strings:
    $key_3a80 = { 69 ef [2] 4d e1 [2] 66 cd [2] 48 ef [2] 5c f4 [2] 53 ee [2] 4d f3 [2] 4f f2 [2] 54 f4 [2] 48 f3 [2] 54 dc }

  condition:
    any of them
}