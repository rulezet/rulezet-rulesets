rule TTP_XOR_QUAD_CurrentVersionRun_b972 {
  strings:
    $key_b972 = { ea 1d [2] ce 13 [2] e5 3f [2] cb 1d [2] df 06 [2] d0 1c [2] ce 01 [2] cc 00 [2] d7 06 [2] cb 01 [2] d7 2e }

  condition:
    any of them
}