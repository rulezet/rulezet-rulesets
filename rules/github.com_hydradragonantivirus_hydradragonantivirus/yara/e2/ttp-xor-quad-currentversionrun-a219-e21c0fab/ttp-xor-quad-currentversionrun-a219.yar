rule TTP_XOR_QUAD_CurrentVersionRun_a219 {
  strings:
    $key_a219 = { f1 76 [2] d5 78 [2] fe 54 [2] d0 76 [2] c4 6d [2] cb 77 [2] d5 6a [2] d7 6b [2] cc 6d [2] d0 6a [2] cc 45 }

  condition:
    any of them
}