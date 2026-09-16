rule TTP_XOR_QUAD_CurrentVersionRun_a29c {
  strings:
    $key_a29c = { f1 f3 [2] d5 fd [2] fe d1 [2] d0 f3 [2] c4 e8 [2] cb f2 [2] d5 ef [2] d7 ee [2] cc e8 [2] d0 ef [2] cc c0 }

  condition:
    any of them
}