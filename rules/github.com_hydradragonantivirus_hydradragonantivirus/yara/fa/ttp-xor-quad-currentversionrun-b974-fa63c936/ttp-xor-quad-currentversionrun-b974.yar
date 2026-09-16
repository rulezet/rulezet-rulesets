rule TTP_XOR_QUAD_CurrentVersionRun_b974 {
  strings:
    $key_b974 = { ea 1b [2] ce 15 [2] e5 39 [2] cb 1b [2] df 00 [2] d0 1a [2] ce 07 [2] cc 06 [2] d7 00 [2] cb 07 [2] d7 28 }

  condition:
    any of them
}