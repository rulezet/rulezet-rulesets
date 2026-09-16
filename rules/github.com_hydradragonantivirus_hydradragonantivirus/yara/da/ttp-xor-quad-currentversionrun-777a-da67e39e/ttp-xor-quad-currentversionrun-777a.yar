rule TTP_XOR_QUAD_CurrentVersionRun_777a {
  strings:
    $key_777a = { 24 15 [2] 00 1b [2] 2b 37 [2] 05 15 [2] 11 0e [2] 1e 14 [2] 00 09 [2] 02 08 [2] 19 0e [2] 05 09 [2] 19 26 }

  condition:
    any of them
}