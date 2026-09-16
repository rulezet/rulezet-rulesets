rule TTP_XOR_QUAD_CurrentVersionRun_b914 {
  strings:
    $key_b914 = { ea 7b [2] ce 75 [2] e5 59 [2] cb 7b [2] df 60 [2] d0 7a [2] ce 67 [2] cc 66 [2] d7 60 [2] cb 67 [2] d7 48 }

  condition:
    any of them
}