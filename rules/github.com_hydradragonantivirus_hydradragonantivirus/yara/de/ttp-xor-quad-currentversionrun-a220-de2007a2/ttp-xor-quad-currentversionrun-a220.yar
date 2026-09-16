rule TTP_XOR_QUAD_CurrentVersionRun_a220 {
  strings:
    $key_a220 = { f1 4f [2] d5 41 [2] fe 6d [2] d0 4f [2] c4 54 [2] cb 4e [2] d5 53 [2] d7 52 [2] cc 54 [2] d0 53 [2] cc 7c }

  condition:
    any of them
}