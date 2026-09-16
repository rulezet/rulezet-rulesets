rule TTP_XOR_QUAD_CurrentVersionRun_649d {
  strings:
    $key_649d = { 37 f2 [2] 13 fc [2] 38 d0 [2] 16 f2 [2] 02 e9 [2] 0d f3 [2] 13 ee [2] 11 ef [2] 0a e9 [2] 16 ee [2] 0a c1 }

  condition:
    any of them
}