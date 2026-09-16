rule TTP_XOR_QUAD_CurrentVersionRun_a290 {
  strings:
    $key_a290 = { f1 ff [2] d5 f1 [2] fe dd [2] d0 ff [2] c4 e4 [2] cb fe [2] d5 e3 [2] d7 e2 [2] cc e4 [2] d0 e3 [2] cc cc }

  condition:
    any of them
}