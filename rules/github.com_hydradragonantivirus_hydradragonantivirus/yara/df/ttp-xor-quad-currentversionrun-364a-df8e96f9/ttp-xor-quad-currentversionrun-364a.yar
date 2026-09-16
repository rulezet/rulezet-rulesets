rule TTP_XOR_QUAD_CurrentVersionRun_364a {
  strings:
    $key_364a = { 65 25 [2] 41 2b [2] 6a 07 [2] 44 25 [2] 50 3e [2] 5f 24 [2] 41 39 [2] 43 38 [2] 58 3e [2] 44 39 [2] 58 16 }

  condition:
    any of them
}