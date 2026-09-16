rule TTP_XOR_QUAD_CurrentVersionRun_b978 {
  strings:
    $key_b978 = { ea 17 [2] ce 19 [2] e5 35 [2] cb 17 [2] df 0c [2] d0 16 [2] ce 0b [2] cc 0a [2] d7 0c [2] cb 0b [2] d7 24 }

  condition:
    any of them
}