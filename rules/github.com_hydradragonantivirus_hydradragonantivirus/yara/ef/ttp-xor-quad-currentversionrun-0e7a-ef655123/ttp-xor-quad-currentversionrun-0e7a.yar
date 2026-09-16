rule TTP_XOR_QUAD_CurrentVersionRun_0e7a {
  strings:
    $key_0e7a = { 5d 15 [2] 79 1b [2] 52 37 [2] 7c 15 [2] 68 0e [2] 67 14 [2] 79 09 [2] 7b 08 [2] 60 0e [2] 7c 09 [2] 60 26 }

  condition:
    any of them
}