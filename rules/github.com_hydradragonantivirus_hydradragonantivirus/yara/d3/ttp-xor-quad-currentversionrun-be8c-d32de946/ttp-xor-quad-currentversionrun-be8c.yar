rule TTP_XOR_QUAD_CurrentVersionRun_be8c {
  strings:
    $key_be8c = { ed e3 [2] c9 ed [2] e2 c1 [2] cc e3 [2] d8 f8 [2] d7 e2 [2] c9 ff [2] cb fe [2] d0 f8 [2] cc ff [2] d0 d0 }

  condition:
    any of them
}