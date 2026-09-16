rule TTP_XOR_QUAD_CurrentVersionRun_b966 {
  strings:
    $key_b966 = { ea 09 [2] ce 07 [2] e5 2b [2] cb 09 [2] df 12 [2] d0 08 [2] ce 15 [2] cc 14 [2] d7 12 [2] cb 15 [2] d7 3a }

  condition:
    any of them
}