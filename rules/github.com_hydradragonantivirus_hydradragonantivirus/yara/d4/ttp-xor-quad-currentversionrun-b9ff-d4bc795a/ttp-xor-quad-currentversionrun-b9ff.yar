rule TTP_XOR_QUAD_CurrentVersionRun_b9ff {
  strings:
    $key_b9ff = { ea 90 [2] ce 9e [2] e5 b2 [2] cb 90 [2] df 8b [2] d0 91 [2] ce 8c [2] cc 8d [2] d7 8b [2] cb 8c [2] d7 a3 }

  condition:
    any of them
}