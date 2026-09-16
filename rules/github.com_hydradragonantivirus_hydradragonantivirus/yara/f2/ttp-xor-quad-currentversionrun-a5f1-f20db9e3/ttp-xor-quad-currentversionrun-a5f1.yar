rule TTP_XOR_QUAD_CurrentVersionRun_a5f1 {
  strings:
    $key_a5f1 = { f6 9e [2] d2 90 [2] f9 bc [2] d7 9e [2] c3 85 [2] cc 9f [2] d2 82 [2] d0 83 [2] cb 85 [2] d7 82 [2] cb ad }

  condition:
    any of them
}