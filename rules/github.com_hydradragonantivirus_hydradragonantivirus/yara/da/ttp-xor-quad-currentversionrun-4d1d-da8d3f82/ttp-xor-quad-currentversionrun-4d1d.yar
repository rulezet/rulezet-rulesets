rule TTP_XOR_QUAD_CurrentVersionRun_4d1d {
  strings:
    $key_4d1d = { 1e 72 [2] 3a 7c [2] 11 50 [2] 3f 72 [2] 2b 69 [2] 24 73 [2] 3a 6e [2] 38 6f [2] 23 69 [2] 3f 6e [2] 23 41 }

  condition:
    any of them
}