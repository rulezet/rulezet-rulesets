rule TTP_XOR_QUAD_CurrentVersionRun_029c {
  strings:
    $key_029c = { 51 f3 [2] 75 fd [2] 5e d1 [2] 70 f3 [2] 64 e8 [2] 6b f2 [2] 75 ef [2] 77 ee [2] 6c e8 [2] 70 ef [2] 6c c0 }

  condition:
    any of them
}