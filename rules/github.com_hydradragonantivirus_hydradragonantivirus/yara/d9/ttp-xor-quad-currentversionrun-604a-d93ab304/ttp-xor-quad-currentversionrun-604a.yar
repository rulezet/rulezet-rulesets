rule TTP_XOR_QUAD_CurrentVersionRun_604a {
  strings:
    $key_604a = { 33 25 [2] 17 2b [2] 3c 07 [2] 12 25 [2] 06 3e [2] 09 24 [2] 17 39 [2] 15 38 [2] 0e 3e [2] 12 39 [2] 0e 16 }

  condition:
    any of them
}