rule TTP_XOR_QUAD_CurrentVersionRun_750a {
  strings:
    $key_750a = { 26 65 [2] 02 6b [2] 29 47 [2] 07 65 [2] 13 7e [2] 1c 64 [2] 02 79 [2] 00 78 [2] 1b 7e [2] 07 79 [2] 1b 56 }

  condition:
    any of them
}