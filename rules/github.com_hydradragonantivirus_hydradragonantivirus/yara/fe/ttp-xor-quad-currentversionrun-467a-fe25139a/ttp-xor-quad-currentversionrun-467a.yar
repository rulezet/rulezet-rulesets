rule TTP_XOR_QUAD_CurrentVersionRun_467a {
  strings:
    $key_467a = { 15 15 [2] 31 1b [2] 1a 37 [2] 34 15 [2] 20 0e [2] 2f 14 [2] 31 09 [2] 33 08 [2] 28 0e [2] 34 09 [2] 28 26 }

  condition:
    any of them
}