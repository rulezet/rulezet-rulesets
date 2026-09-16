rule TTP_XOR_QUAD_CurrentVersionRun_5d7f {
  strings:
    $key_5d7f = { 0e 10 [2] 2a 1e [2] 01 32 [2] 2f 10 [2] 3b 0b [2] 34 11 [2] 2a 0c [2] 28 0d [2] 33 0b [2] 2f 0c [2] 33 23 }

  condition:
    any of them
}