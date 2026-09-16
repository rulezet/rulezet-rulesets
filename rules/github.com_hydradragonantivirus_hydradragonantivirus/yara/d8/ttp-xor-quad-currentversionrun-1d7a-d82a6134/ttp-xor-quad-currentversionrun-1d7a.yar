rule TTP_XOR_QUAD_CurrentVersionRun_1d7a {
  strings:
    $key_1d7a = { 4e 15 [2] 6a 1b [2] 41 37 [2] 6f 15 [2] 7b 0e [2] 74 14 [2] 6a 09 [2] 68 08 [2] 73 0e [2] 6f 09 [2] 73 26 }

  condition:
    any of them
}