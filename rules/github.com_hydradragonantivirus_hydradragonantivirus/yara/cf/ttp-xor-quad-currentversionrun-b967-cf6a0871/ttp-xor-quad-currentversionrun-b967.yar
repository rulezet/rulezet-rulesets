rule TTP_XOR_QUAD_CurrentVersionRun_b967 {
  strings:
    $key_b967 = { ea 08 [2] ce 06 [2] e5 2a [2] cb 08 [2] df 13 [2] d0 09 [2] ce 14 [2] cc 15 [2] d7 13 [2] cb 14 [2] d7 3b }

  condition:
    any of them
}