rule TTP_XOR_QUAD_CurrentVersionRun_be81 {
  strings:
    $key_be81 = { ed ee [2] c9 e0 [2] e2 cc [2] cc ee [2] d8 f5 [2] d7 ef [2] c9 f2 [2] cb f3 [2] d0 f5 [2] cc f2 [2] d0 dd }

  condition:
    any of them
}