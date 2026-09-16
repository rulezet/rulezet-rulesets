rule TTP_XOR_QUAD_CurrentVersionRun_a23a {
  strings:
    $key_a23a = { f1 55 [2] d5 5b [2] fe 77 [2] d0 55 [2] c4 4e [2] cb 54 [2] d5 49 [2] d7 48 [2] cc 4e [2] d0 49 [2] cc 66 }

  condition:
    any of them
}