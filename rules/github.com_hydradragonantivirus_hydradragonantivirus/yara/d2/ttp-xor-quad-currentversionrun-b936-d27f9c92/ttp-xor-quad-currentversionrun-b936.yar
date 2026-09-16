rule TTP_XOR_QUAD_CurrentVersionRun_b936 {
  strings:
    $key_b936 = { ea 59 [2] ce 57 [2] e5 7b [2] cb 59 [2] df 42 [2] d0 58 [2] ce 45 [2] cc 44 [2] d7 42 [2] cb 45 [2] d7 6a }

  condition:
    any of them
}