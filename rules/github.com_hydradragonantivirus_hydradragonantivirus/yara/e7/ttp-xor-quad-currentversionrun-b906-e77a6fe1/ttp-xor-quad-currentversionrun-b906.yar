rule TTP_XOR_QUAD_CurrentVersionRun_b906 {
  strings:
    $key_b906 = { ea 69 [2] ce 67 [2] e5 4b [2] cb 69 [2] df 72 [2] d0 68 [2] ce 75 [2] cc 74 [2] d7 72 [2] cb 75 [2] d7 5a }

  condition:
    any of them
}