rule TTP_XOR_QUAD_CurrentVersionRun_7c3a {
  strings:
    $key_7c3a = { 2f 55 [2] 0b 5b [2] 20 77 [2] 0e 55 [2] 1a 4e [2] 15 54 [2] 0b 49 [2] 09 48 [2] 12 4e [2] 0e 49 [2] 12 66 }

  condition:
    any of them
}