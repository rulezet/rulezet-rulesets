rule TTP_XOR_QUAD_CurrentVersionRun_a2be {
  strings:
    $key_a2be = { f1 d1 [2] d5 df [2] fe f3 [2] d0 d1 [2] c4 ca [2] cb d0 [2] d5 cd [2] d7 cc [2] cc ca [2] d0 cd [2] cc e2 }

  condition:
    any of them
}