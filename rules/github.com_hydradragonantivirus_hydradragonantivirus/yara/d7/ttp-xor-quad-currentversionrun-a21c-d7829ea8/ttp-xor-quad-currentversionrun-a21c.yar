rule TTP_XOR_QUAD_CurrentVersionRun_a21c {
  strings:
    $key_a21c = { f1 73 [2] d5 7d [2] fe 51 [2] d0 73 [2] c4 68 [2] cb 72 [2] d5 6f [2] d7 6e [2] cc 68 [2] d0 6f [2] cc 40 }

  condition:
    any of them
}