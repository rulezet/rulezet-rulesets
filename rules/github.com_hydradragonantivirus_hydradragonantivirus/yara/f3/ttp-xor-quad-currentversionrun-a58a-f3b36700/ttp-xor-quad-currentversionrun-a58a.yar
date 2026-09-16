rule TTP_XOR_QUAD_CurrentVersionRun_a58a {
  strings:
    $key_a58a = { f6 e5 [2] d2 eb [2] f9 c7 [2] d7 e5 [2] c3 fe [2] cc e4 [2] d2 f9 [2] d0 f8 [2] cb fe [2] d7 f9 [2] cb d6 }

  condition:
    any of them
}