rule TTP_XOR_QUAD_CurrentVersionRun_b953 {
  strings:
    $key_b953 = { ea 3c [2] ce 32 [2] e5 1e [2] cb 3c [2] df 27 [2] d0 3d [2] ce 20 [2] cc 21 [2] d7 27 [2] cb 20 [2] d7 0f }

  condition:
    any of them
}