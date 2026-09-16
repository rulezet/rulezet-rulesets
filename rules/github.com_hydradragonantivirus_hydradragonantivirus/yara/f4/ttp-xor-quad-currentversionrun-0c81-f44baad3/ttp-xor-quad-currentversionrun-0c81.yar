rule TTP_XOR_QUAD_CurrentVersionRun_0c81 {
  strings:
    $key_0c81 = { 5f ee [2] 7b e0 [2] 50 cc [2] 7e ee [2] 6a f5 [2] 65 ef [2] 7b f2 [2] 79 f3 [2] 62 f5 [2] 7e f2 [2] 62 dd }

  condition:
    any of them
}