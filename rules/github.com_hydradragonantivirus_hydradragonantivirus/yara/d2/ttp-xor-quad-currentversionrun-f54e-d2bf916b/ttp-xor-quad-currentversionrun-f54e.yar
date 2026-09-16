rule TTP_XOR_QUAD_CurrentVersionRun_f54e {
  strings:
    $key_f54e = { a6 21 [2] 82 2f [2] a9 03 [2] 87 21 [2] 93 3a [2] 9c 20 [2] 82 3d [2] 80 3c [2] 9b 3a [2] 87 3d [2] 9b 12 }

  condition:
    any of them
}