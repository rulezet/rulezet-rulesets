rule TTP_XOR_QUAD_CurrentVersionRun_339d {
  strings:
    $key_339d = { 60 f2 [2] 44 fc [2] 6f d0 [2] 41 f2 [2] 55 e9 [2] 5a f3 [2] 44 ee [2] 46 ef [2] 5d e9 [2] 41 ee [2] 5d c1 }

  condition:
    any of them
}