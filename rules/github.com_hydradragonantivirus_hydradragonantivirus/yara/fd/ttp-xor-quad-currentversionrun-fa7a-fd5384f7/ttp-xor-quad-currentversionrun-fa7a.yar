rule TTP_XOR_QUAD_CurrentVersionRun_fa7a {
  strings:
    $key_fa7a = { a9 15 [2] 8d 1b [2] a6 37 [2] 88 15 [2] 9c 0e [2] 93 14 [2] 8d 09 [2] 8f 08 [2] 94 0e [2] 88 09 [2] 94 26 }

  condition:
    any of them
}