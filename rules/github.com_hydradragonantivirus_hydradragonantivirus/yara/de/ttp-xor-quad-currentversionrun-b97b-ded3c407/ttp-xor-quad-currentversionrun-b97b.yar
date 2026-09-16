rule TTP_XOR_QUAD_CurrentVersionRun_b97b {
  strings:
    $key_b97b = { ea 14 [2] ce 1a [2] e5 36 [2] cb 14 [2] df 0f [2] d0 15 [2] ce 08 [2] cc 09 [2] d7 0f [2] cb 08 [2] d7 27 }

  condition:
    any of them
}