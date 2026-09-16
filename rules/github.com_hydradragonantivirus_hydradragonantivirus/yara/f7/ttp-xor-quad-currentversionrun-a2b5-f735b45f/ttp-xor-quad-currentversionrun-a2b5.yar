rule TTP_XOR_QUAD_CurrentVersionRun_a2b5 {
  strings:
    $key_a2b5 = { f1 da [2] d5 d4 [2] fe f8 [2] d0 da [2] c4 c1 [2] cb db [2] d5 c6 [2] d7 c7 [2] cc c1 [2] d0 c6 [2] cc e9 }

  condition:
    any of them
}