rule TTP_XOR_QUAD_CurrentVersionRun_b903 {
  strings:
    $key_b903 = { ea 6c [2] ce 62 [2] e5 4e [2] cb 6c [2] df 77 [2] d0 6d [2] ce 70 [2] cc 71 [2] d7 77 [2] cb 70 [2] d7 5f }

  condition:
    any of them
}