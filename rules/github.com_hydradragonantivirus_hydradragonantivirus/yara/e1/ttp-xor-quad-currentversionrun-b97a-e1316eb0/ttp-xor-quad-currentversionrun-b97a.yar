rule TTP_XOR_QUAD_CurrentVersionRun_b97a {
  strings:
    $key_b97a = { ea 15 [2] ce 1b [2] e5 37 [2] cb 15 [2] df 0e [2] d0 14 [2] ce 09 [2] cc 08 [2] d7 0e [2] cb 09 [2] d7 26 }

  condition:
    any of them
}