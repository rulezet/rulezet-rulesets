rule TTP_XOR_QUAD_CurrentVersionRun_0c6f {
  strings:
    $key_0c6f = { 5f 00 [2] 7b 0e [2] 50 22 [2] 7e 00 [2] 6a 1b [2] 65 01 [2] 7b 1c [2] 79 1d [2] 62 1b [2] 7e 1c [2] 62 33 }

  condition:
    any of them
}