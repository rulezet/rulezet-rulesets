rule TTP_XOR_QUAD_CurrentVersionRun_a52d {
  strings:
    $key_a52d = { f6 42 [2] d2 4c [2] f9 60 [2] d7 42 [2] c3 59 [2] cc 43 [2] d2 5e [2] d0 5f [2] cb 59 [2] d7 5e [2] cb 71 }

  condition:
    any of them
}