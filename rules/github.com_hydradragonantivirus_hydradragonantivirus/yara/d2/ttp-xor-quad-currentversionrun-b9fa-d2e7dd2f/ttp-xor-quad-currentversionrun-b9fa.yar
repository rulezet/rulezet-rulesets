rule TTP_XOR_QUAD_CurrentVersionRun_b9fa {
  strings:
    $key_b9fa = { ea 95 [2] ce 9b [2] e5 b7 [2] cb 95 [2] df 8e [2] d0 94 [2] ce 89 [2] cc 88 [2] d7 8e [2] cb 89 [2] d7 a6 }

  condition:
    any of them
}