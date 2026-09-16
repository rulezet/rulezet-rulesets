rule TTP_XOR_QUAD_CurrentVersionRun_4d0a {
  strings:
    $key_4d0a = { 1e 65 [2] 3a 6b [2] 11 47 [2] 3f 65 [2] 2b 7e [2] 24 64 [2] 3a 79 [2] 38 78 [2] 23 7e [2] 3f 79 [2] 23 56 }

  condition:
    any of them
}