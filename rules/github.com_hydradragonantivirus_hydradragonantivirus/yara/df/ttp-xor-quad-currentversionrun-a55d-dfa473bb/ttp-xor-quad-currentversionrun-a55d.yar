rule TTP_XOR_QUAD_CurrentVersionRun_a55d {
  strings:
    $key_a55d = { f6 32 [2] d2 3c [2] f9 10 [2] d7 32 [2] c3 29 [2] cc 33 [2] d2 2e [2] d0 2f [2] cb 29 [2] d7 2e [2] cb 01 }

  condition:
    any of them
}