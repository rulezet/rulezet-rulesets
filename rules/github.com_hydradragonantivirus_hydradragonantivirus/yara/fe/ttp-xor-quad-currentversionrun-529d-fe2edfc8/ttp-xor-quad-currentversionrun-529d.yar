rule TTP_XOR_QUAD_CurrentVersionRun_529d {
  strings:
    $key_529d = { 01 f2 [2] 25 fc [2] 0e d0 [2] 20 f2 [2] 34 e9 [2] 3b f3 [2] 25 ee [2] 27 ef [2] 3c e9 [2] 20 ee [2] 3c c1 }

  condition:
    any of them
}