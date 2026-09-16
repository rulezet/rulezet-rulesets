rule TTP_XOR_QUAD_CurrentVersionRun_a55c {
  strings:
    $key_a55c = { f6 33 [2] d2 3d [2] f9 11 [2] d7 33 [2] c3 28 [2] cc 32 [2] d2 2f [2] d0 2e [2] cb 28 [2] d7 2f [2] cb 00 }

  condition:
    any of them
}