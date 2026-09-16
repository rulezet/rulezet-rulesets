rule TTP_XOR_QUAD_CurrentVersionRun_b964 {
  strings:
    $key_b964 = { ea 0b [2] ce 05 [2] e5 29 [2] cb 0b [2] df 10 [2] d0 0a [2] ce 17 [2] cc 16 [2] d7 10 [2] cb 17 [2] d7 38 }

  condition:
    any of them
}