rule TTP_XOR_QUAD_CurrentVersionRun_797f {
  strings:
    $key_797f = { 2a 10 [2] 0e 1e [2] 25 32 [2] 0b 10 [2] 1f 0b [2] 10 11 [2] 0e 0c [2] 0c 0d [2] 17 0b [2] 0b 0c [2] 17 23 }

  condition:
    any of them
}