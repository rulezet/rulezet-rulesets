rule TTP_XOR_QUAD_CurrentVersionRun_b945 {
  strings:
    $key_b945 = { ea 2a [2] ce 24 [2] e5 08 [2] cb 2a [2] df 31 [2] d0 2b [2] ce 36 [2] cc 37 [2] d7 31 [2] cb 36 [2] d7 19 }

  condition:
    any of them
}