rule TTP_XOR_QUAD_CurrentVersionRun_fa7e {
  strings:
    $key_fa7e = { a9 11 [2] 8d 1f [2] a6 33 [2] 88 11 [2] 9c 0a [2] 93 10 [2] 8d 0d [2] 8f 0c [2] 94 0a [2] 88 0d [2] 94 22 }

  condition:
    any of them
}