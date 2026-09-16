rule TTP_XOR_QUAD_CurrentVersionRun_5481 {
  strings:
    $key_5481 = { 07 ee [2] 23 e0 [2] 08 cc [2] 26 ee [2] 32 f5 [2] 3d ef [2] 23 f2 [2] 21 f3 [2] 3a f5 [2] 26 f2 [2] 3a dd }

  condition:
    any of them
}