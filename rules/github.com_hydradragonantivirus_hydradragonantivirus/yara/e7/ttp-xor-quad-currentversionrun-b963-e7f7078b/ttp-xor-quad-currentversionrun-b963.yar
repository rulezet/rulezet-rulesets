rule TTP_XOR_QUAD_CurrentVersionRun_b963 {
  strings:
    $key_b963 = { ea 0c [2] ce 02 [2] e5 2e [2] cb 0c [2] df 17 [2] d0 0d [2] ce 10 [2] cc 11 [2] d7 17 [2] cb 10 [2] d7 3f }

  condition:
    any of them
}