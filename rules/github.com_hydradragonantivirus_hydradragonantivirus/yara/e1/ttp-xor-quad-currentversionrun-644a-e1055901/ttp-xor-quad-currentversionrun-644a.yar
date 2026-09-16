rule TTP_XOR_QUAD_CurrentVersionRun_644a {
  strings:
    $key_644a = { 37 25 [2] 13 2b [2] 38 07 [2] 16 25 [2] 02 3e [2] 0d 24 [2] 13 39 [2] 11 38 [2] 0a 3e [2] 16 39 [2] 0a 16 }

  condition:
    any of them
}