rule TTP_XOR_QUAD_CurrentVersionRun_f881 {
  strings:
    $key_f881 = { ab ee [2] 8f e0 [2] a4 cc [2] 8a ee [2] 9e f5 [2] 91 ef [2] 8f f2 [2] 8d f3 [2] 96 f5 [2] 8a f2 [2] 96 dd }

  condition:
    any of them
}