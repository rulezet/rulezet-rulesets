rule TTP_XOR_QUAD_CurrentVersionRun_673a {
  strings:
    $key_673a = { 34 55 [2] 10 5b [2] 3b 77 [2] 15 55 [2] 01 4e [2] 0e 54 [2] 10 49 [2] 12 48 [2] 09 4e [2] 15 49 [2] 09 66 }

  condition:
    any of them
}