rule TTP_XOR_QUAD_CurrentVersionRun_a281 {
  strings:
    $key_a281 = { f1 ee [2] d5 e0 [2] fe cc [2] d0 ee [2] c4 f5 [2] cb ef [2] d5 f2 [2] d7 f3 [2] cc f5 [2] d0 f2 [2] cc dd }

  condition:
    any of them
}