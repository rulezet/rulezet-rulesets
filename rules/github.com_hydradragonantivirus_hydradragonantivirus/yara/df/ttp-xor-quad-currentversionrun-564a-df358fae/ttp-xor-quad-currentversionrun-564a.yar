rule TTP_XOR_QUAD_CurrentVersionRun_564a {
  strings:
    $key_564a = { 05 25 [2] 21 2b [2] 0a 07 [2] 24 25 [2] 30 3e [2] 3f 24 [2] 21 39 [2] 23 38 [2] 38 3e [2] 24 39 [2] 38 16 }

  condition:
    any of them
}