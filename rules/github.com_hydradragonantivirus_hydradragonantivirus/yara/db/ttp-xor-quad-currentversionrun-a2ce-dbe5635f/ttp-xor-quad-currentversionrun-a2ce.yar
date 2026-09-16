rule TTP_XOR_QUAD_CurrentVersionRun_a2ce {
  strings:
    $key_a2ce = { f1 a1 [2] d5 af [2] fe 83 [2] d0 a1 [2] c4 ba [2] cb a0 [2] d5 bd [2] d7 bc [2] cc ba [2] d0 bd [2] cc 92 }

  condition:
    any of them
}