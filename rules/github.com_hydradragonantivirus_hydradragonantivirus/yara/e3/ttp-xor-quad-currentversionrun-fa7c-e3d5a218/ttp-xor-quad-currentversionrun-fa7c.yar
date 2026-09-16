rule TTP_XOR_QUAD_CurrentVersionRun_fa7c {
  strings:
    $key_fa7c = { a9 13 [2] 8d 1d [2] a6 31 [2] 88 13 [2] 9c 08 [2] 93 12 [2] 8d 0f [2] 8f 0e [2] 94 08 [2] 88 0f [2] 94 20 }

  condition:
    any of them
}