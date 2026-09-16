rule TTP_XOR_QUAD_CurrentVersionRun_b946 {
  strings:
    $key_b946 = { ea 29 [2] ce 27 [2] e5 0b [2] cb 29 [2] df 32 [2] d0 28 [2] ce 35 [2] cc 34 [2] d7 32 [2] cb 35 [2] d7 1a }

  condition:
    any of them
}