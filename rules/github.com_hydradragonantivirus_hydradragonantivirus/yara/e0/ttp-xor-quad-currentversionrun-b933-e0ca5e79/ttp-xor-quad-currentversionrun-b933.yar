rule TTP_XOR_QUAD_CurrentVersionRun_b933 {
  strings:
    $key_b933 = { ea 5c [2] ce 52 [2] e5 7e [2] cb 5c [2] df 47 [2] d0 5d [2] ce 40 [2] cc 41 [2] d7 47 [2] cb 40 [2] d7 6f }

  condition:
    any of them
}