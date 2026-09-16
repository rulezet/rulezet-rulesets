rule TTP_XOR_QUAD_CurrentVersionRun_317f {
  strings:
    $key_317f = { 62 10 [2] 46 1e [2] 6d 32 [2] 43 10 [2] 57 0b [2] 58 11 [2] 46 0c [2] 44 0d [2] 5f 0b [2] 43 0c [2] 5f 23 }

  condition:
    any of them
}