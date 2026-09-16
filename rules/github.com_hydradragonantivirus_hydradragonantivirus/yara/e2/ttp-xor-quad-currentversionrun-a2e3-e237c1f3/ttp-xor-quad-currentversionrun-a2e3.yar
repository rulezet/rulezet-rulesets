rule TTP_XOR_QUAD_CurrentVersionRun_a2e3 {
  strings:
    $key_a2e3 = { f1 8c [2] d5 82 [2] fe ae [2] d0 8c [2] c4 97 [2] cb 8d [2] d5 90 [2] d7 91 [2] cc 97 [2] d0 90 [2] cc bf }

  condition:
    any of them
}