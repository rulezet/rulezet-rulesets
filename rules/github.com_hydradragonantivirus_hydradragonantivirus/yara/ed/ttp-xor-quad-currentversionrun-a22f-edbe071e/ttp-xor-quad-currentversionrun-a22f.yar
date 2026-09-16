rule TTP_XOR_QUAD_CurrentVersionRun_a22f {
  strings:
    $key_a22f = { f1 40 [2] d5 4e [2] fe 62 [2] d0 40 [2] c4 5b [2] cb 41 [2] d5 5c [2] d7 5d [2] cc 5b [2] d0 5c [2] cc 73 }

  condition:
    any of them
}