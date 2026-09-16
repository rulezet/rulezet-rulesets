rule TTP_XOR_QUAD_CurrentVersionRun_b935 {
  strings:
    $key_b935 = { ea 5a [2] ce 54 [2] e5 78 [2] cb 5a [2] df 41 [2] d0 5b [2] ce 46 [2] cc 47 [2] d7 41 [2] cb 46 [2] d7 69 }

  condition:
    any of them
}