rule TTP_XOR_QUAD_CurrentVersionRun_417f {
  strings:
    $key_417f = { 12 10 [2] 36 1e [2] 1d 32 [2] 33 10 [2] 27 0b [2] 28 11 [2] 36 0c [2] 34 0d [2] 2f 0b [2] 33 0c [2] 2f 23 }

  condition:
    any of them
}