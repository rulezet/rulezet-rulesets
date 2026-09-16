rule TTP_XOR_QUAD_CurrentVersionRun_4ded {
  strings:
    $key_4ded = { 1e 82 [2] 3a 8c [2] 11 a0 [2] 3f 82 [2] 2b 99 [2] 24 83 [2] 3a 9e [2] 38 9f [2] 23 99 [2] 3f 9e [2] 23 b1 }

  condition:
    any of them
}