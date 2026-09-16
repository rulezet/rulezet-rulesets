rule TTP_XOR_QUAD_CurrentVersionRun_4c81 {
  strings:
    $key_4c81 = { 1f ee [2] 3b e0 [2] 10 cc [2] 3e ee [2] 2a f5 [2] 25 ef [2] 3b f2 [2] 39 f3 [2] 22 f5 [2] 3e f2 [2] 22 dd }

  condition:
    any of them
}