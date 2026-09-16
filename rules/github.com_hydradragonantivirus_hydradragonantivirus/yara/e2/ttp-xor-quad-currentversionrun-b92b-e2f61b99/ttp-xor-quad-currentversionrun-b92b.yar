rule TTP_XOR_QUAD_CurrentVersionRun_b92b {
  strings:
    $key_b92b = { ea 44 [2] ce 4a [2] e5 66 [2] cb 44 [2] df 5f [2] d0 45 [2] ce 58 [2] cc 59 [2] d7 5f [2] cb 58 [2] d7 77 }

  condition:
    any of them
}