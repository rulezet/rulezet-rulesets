rule TTP_XOR_QUAD_CurrentVersionRun_bcb4 {
  strings:
    $key_bcb4 = { ef db [2] cb d5 [2] e0 f9 [2] ce db [2] da c0 [2] d5 da [2] cb c7 [2] c9 c6 [2] d2 c0 [2] ce c7 [2] d2 e8 }

  condition:
    any of them
}