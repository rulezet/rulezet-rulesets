rule TTP_XOR_QUAD_CurrentVersionRun_629d {
  strings:
    $key_629d = { 31 f2 [2] 15 fc [2] 3e d0 [2] 10 f2 [2] 04 e9 [2] 0b f3 [2] 15 ee [2] 17 ef [2] 0c e9 [2] 10 ee [2] 0c c1 }

  condition:
    any of them
}