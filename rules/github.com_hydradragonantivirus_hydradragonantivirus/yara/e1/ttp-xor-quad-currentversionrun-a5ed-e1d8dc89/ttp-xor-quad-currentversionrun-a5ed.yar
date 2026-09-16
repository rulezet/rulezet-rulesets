rule TTP_XOR_QUAD_CurrentVersionRun_a5ed {
  strings:
    $key_a5ed = { f6 82 [2] d2 8c [2] f9 a0 [2] d7 82 [2] c3 99 [2] cc 83 [2] d2 9e [2] d0 9f [2] cb 99 [2] d7 9e [2] cb b1 }

  condition:
    any of them
}