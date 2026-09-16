rule TTP_XOR_QUAD_CurrentVersionRun_b94d {
  strings:
    $key_b94d = { ea 22 [2] ce 2c [2] e5 00 [2] cb 22 [2] df 39 [2] d0 23 [2] ce 3e [2] cc 3f [2] d7 39 [2] cb 3e [2] d7 11 }

  condition:
    any of them
}