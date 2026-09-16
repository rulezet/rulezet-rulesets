rule TTP_XOR_QUAD_CurrentVersionRun_a287 {
  strings:
    $key_a287 = { f1 e8 [2] d5 e6 [2] fe ca [2] d0 e8 [2] c4 f3 [2] cb e9 [2] d5 f4 [2] d7 f5 [2] cc f3 [2] d0 f4 [2] cc db }

  condition:
    any of them
}