rule TTP_XOR_QUAD_CurrentVersionRun_b95d {
  strings:
    $key_b95d = { ea 32 [2] ce 3c [2] e5 10 [2] cb 32 [2] df 29 [2] d0 33 [2] ce 2e [2] cc 2f [2] d7 29 [2] cb 2e [2] d7 01 }

  condition:
    any of them
}