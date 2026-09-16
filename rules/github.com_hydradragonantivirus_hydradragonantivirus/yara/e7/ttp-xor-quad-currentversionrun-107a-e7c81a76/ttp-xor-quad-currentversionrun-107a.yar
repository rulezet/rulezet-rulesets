rule TTP_XOR_QUAD_CurrentVersionRun_107a {
  strings:
    $key_107a = { 43 15 [2] 67 1b [2] 4c 37 [2] 62 15 [2] 76 0e [2] 79 14 [2] 67 09 [2] 65 08 [2] 7e 0e [2] 62 09 [2] 7e 26 }

  condition:
    any of them
}