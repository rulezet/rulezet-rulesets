rule TTP_XOR_QUAD_CurrentVersionRun_129d {
  strings:
    $key_129d = { 41 f2 [2] 65 fc [2] 4e d0 [2] 60 f2 [2] 74 e9 [2] 7b f3 [2] 65 ee [2] 67 ef [2] 7c e9 [2] 60 ee [2] 7c c1 }

  condition:
    any of them
}