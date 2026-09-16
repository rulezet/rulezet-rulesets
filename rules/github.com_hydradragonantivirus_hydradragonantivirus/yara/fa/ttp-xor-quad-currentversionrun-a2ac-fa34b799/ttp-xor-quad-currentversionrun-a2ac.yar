rule TTP_XOR_QUAD_CurrentVersionRun_a2ac {
  strings:
    $key_a2ac = { f1 c3 [2] d5 cd [2] fe e1 [2] d0 c3 [2] c4 d8 [2] cb c2 [2] d5 df [2] d7 de [2] cc d8 [2] d0 df [2] cc f0 }

  condition:
    any of them
}