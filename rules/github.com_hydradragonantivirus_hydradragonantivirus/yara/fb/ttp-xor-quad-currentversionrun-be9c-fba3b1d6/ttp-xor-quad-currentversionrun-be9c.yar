rule TTP_XOR_QUAD_CurrentVersionRun_be9c {
  strings:
    $key_be9c = { ed f3 [2] c9 fd [2] e2 d1 [2] cc f3 [2] d8 e8 [2] d7 f2 [2] c9 ef [2] cb ee [2] d0 e8 [2] cc ef [2] d0 c0 }

  condition:
    any of them
}