rule TTP_XOR_QUAD_CurrentVersionRun_b95c {
  strings:
    $key_b95c = { ea 33 [2] ce 3d [2] e5 11 [2] cb 33 [2] df 28 [2] d0 32 [2] ce 2f [2] cc 2e [2] d7 28 [2] cb 2f [2] d7 00 }

  condition:
    any of them
}