rule TTP_XOR_QUAD_CurrentVersionRun_567a {
  strings:
    $key_567a = { 05 15 [2] 21 1b [2] 0a 37 [2] 24 15 [2] 30 0e [2] 3f 14 [2] 21 09 [2] 23 08 [2] 38 0e [2] 24 09 [2] 38 26 }

  condition:
    any of them
}