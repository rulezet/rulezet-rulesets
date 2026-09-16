rule TTP_XOR_QUAD_CurrentVersionRun_b95f {
  strings:
    $key_b95f = { ea 30 [2] ce 3e [2] e5 12 [2] cb 30 [2] df 2b [2] d0 31 [2] ce 2c [2] cc 2d [2] d7 2b [2] cb 2c [2] d7 03 }

  condition:
    any of them
}