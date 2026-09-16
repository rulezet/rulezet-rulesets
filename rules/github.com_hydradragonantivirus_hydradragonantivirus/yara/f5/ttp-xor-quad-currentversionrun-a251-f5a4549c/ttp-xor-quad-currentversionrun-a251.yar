rule TTP_XOR_QUAD_CurrentVersionRun_a251 {
  strings:
    $key_a251 = { f1 3e [2] d5 30 [2] fe 1c [2] d0 3e [2] c4 25 [2] cb 3f [2] d5 22 [2] d7 23 [2] cc 25 [2] d0 22 [2] cc 0d }

  condition:
    any of them
}