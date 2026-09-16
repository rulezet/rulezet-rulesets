rule TTP_XOR_QUAD_CurrentVersionRun_b929 {
  strings:
    $key_b929 = { ea 46 [2] ce 48 [2] e5 64 [2] cb 46 [2] df 5d [2] d0 47 [2] ce 5a [2] cc 5b [2] d7 5d [2] cb 5a [2] d7 75 }

  condition:
    any of them
}