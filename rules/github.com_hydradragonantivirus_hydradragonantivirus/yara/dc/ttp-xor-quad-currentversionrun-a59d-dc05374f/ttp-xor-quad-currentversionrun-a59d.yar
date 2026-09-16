rule TTP_XOR_QUAD_CurrentVersionRun_a59d {
  strings:
    $key_a59d = { f6 f2 [2] d2 fc [2] f9 d0 [2] d7 f2 [2] c3 e9 [2] cc f3 [2] d2 ee [2] d0 ef [2] cb e9 [2] d7 ee [2] cb c1 }

  condition:
    any of them
}