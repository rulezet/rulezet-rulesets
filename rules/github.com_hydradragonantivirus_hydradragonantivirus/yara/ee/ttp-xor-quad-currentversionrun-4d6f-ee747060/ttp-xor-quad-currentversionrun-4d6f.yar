rule TTP_XOR_QUAD_CurrentVersionRun_4d6f {
  strings:
    $key_4d6f = { 1e 00 [2] 3a 0e [2] 11 22 [2] 3f 00 [2] 2b 1b [2] 24 01 [2] 3a 1c [2] 38 1d [2] 23 1b [2] 3f 1c [2] 23 33 }

  condition:
    any of them
}