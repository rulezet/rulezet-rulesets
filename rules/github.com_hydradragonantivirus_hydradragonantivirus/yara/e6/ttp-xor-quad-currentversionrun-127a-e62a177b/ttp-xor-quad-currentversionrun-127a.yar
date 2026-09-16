rule TTP_XOR_QUAD_CurrentVersionRun_127a {
  strings:
    $key_127a = { 41 15 [2] 65 1b [2] 4e 37 [2] 60 15 [2] 74 0e [2] 7b 14 [2] 65 09 [2] 67 08 [2] 7c 0e [2] 60 09 [2] 7c 26 }

  condition:
    any of them
}