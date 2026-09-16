rule TTP_XOR_QUAD_CurrentVersionRun_464a {
  strings:
    $key_464a = { 15 25 [2] 31 2b [2] 1a 07 [2] 34 25 [2] 20 3e [2] 2f 24 [2] 31 39 [2] 33 38 [2] 28 3e [2] 34 39 [2] 28 16 }

  condition:
    any of them
}