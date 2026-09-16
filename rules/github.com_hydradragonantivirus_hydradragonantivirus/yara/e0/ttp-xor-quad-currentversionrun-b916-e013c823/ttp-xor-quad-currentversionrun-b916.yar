rule TTP_XOR_QUAD_CurrentVersionRun_b916 {
  strings:
    $key_b916 = { ea 79 [2] ce 77 [2] e5 5b [2] cb 79 [2] df 62 [2] d0 78 [2] ce 65 [2] cc 64 [2] d7 62 [2] cb 65 [2] d7 4a }

  condition:
    any of them
}