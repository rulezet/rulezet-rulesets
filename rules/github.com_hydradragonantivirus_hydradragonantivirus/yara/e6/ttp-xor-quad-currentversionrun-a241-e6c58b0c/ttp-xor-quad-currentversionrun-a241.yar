rule TTP_XOR_QUAD_CurrentVersionRun_a241 {
  strings:
    $key_a241 = { f1 2e [2] d5 20 [2] fe 0c [2] d0 2e [2] c4 35 [2] cb 2f [2] d5 32 [2] d7 33 [2] cc 35 [2] d0 32 [2] cc 1d }

  condition:
    any of them
}