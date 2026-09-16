rule TTP_XOR_QUAD_CurrentVersionRun_f57e {
  strings:
    $key_f57e = { a6 11 [2] 82 1f [2] a9 33 [2] 87 11 [2] 93 0a [2] 9c 10 [2] 82 0d [2] 80 0c [2] 9b 0a [2] 87 0d [2] 9b 22 }

  condition:
    any of them
}