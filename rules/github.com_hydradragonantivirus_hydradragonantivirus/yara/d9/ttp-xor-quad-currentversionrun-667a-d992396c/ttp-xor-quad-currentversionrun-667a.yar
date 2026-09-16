rule TTP_XOR_QUAD_CurrentVersionRun_667a {
  strings:
    $key_667a = { 35 15 [2] 11 1b [2] 3a 37 [2] 14 15 [2] 00 0e [2] 0f 14 [2] 11 09 [2] 13 08 [2] 08 0e [2] 14 09 [2] 08 26 }

  condition:
    any of them
}