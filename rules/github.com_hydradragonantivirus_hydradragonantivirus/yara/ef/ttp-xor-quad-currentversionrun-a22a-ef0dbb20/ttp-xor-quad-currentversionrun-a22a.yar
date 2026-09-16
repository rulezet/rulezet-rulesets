rule TTP_XOR_QUAD_CurrentVersionRun_a22a {
  strings:
    $key_a22a = { f1 45 [2] d5 4b [2] fe 67 [2] d0 45 [2] c4 5e [2] cb 44 [2] d5 59 [2] d7 58 [2] cc 5e [2] d0 59 [2] cc 76 }

  condition:
    any of them
}