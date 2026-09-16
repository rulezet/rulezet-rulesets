rule TTP_XOR_QUAD_CurrentVersionRun_a253 {
  strings:
    $key_a253 = { f1 3c [2] d5 32 [2] fe 1e [2] d0 3c [2] c4 27 [2] cb 3d [2] d5 20 [2] d7 21 [2] cc 27 [2] d0 20 [2] cc 0f }

  condition:
    any of them
}