rule TTP_XOR_QUAD_CurrentVersionRun_6c81 {
  strings:
    $key_6c81 = { 3f ee [2] 1b e0 [2] 30 cc [2] 1e ee [2] 0a f5 [2] 05 ef [2] 1b f2 [2] 19 f3 [2] 02 f5 [2] 1e f2 [2] 02 dd }

  condition:
    any of them
}