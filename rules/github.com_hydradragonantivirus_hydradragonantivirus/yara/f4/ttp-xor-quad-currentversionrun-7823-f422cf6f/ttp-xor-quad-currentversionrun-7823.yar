rule TTP_XOR_QUAD_CurrentVersionRun_7823 {
  strings:
    $key_7823 = { 2b 4c [2] 0f 42 [2] 24 6e [2] 0a 4c [2] 1e 57 [2] 11 4d [2] 0f 50 [2] 0d 51 [2] 16 57 [2] 0a 50 [2] 16 7f }

  condition:
    any of them
}