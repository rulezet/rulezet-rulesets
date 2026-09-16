rule TTP_XOR_QUAD_CurrentVersionRun_be8d {
  strings:
    $key_be8d = { ed e2 [2] c9 ec [2] e2 c0 [2] cc e2 [2] d8 f9 [2] d7 e3 [2] c9 fe [2] cb ff [2] d0 f9 [2] cc fe [2] d0 d1 }

  condition:
    any of them
}