rule TTP_XOR_QUAD_CurrentVersionRun_b957 {
  strings:
    $key_b957 = { ea 38 [2] ce 36 [2] e5 1a [2] cb 38 [2] df 23 [2] d0 39 [2] ce 24 [2] cc 25 [2] d7 23 [2] cb 24 [2] d7 0b }

  condition:
    any of them
}