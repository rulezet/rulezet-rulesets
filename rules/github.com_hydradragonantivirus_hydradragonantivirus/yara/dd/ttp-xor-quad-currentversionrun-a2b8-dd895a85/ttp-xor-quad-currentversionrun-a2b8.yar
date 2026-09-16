rule TTP_XOR_QUAD_CurrentVersionRun_a2b8 {
  strings:
    $key_a2b8 = { f1 d7 [2] d5 d9 [2] fe f5 [2] d0 d7 [2] c4 cc [2] cb d6 [2] d5 cb [2] d7 ca [2] cc cc [2] d0 cb [2] cc e4 }

  condition:
    any of them
}