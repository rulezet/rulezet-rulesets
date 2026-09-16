rule TTP_XOR_QUAD_CurrentVersionRun_a212 {
  strings:
    $key_a212 = { f1 7d [2] d5 73 [2] fe 5f [2] d0 7d [2] c4 66 [2] cb 7c [2] d5 61 [2] d7 60 [2] cc 66 [2] d0 61 [2] cc 4e }

  condition:
    any of them
}