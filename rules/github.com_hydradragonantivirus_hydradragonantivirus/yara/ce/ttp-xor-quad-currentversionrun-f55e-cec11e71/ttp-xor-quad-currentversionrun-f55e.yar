rule TTP_XOR_QUAD_CurrentVersionRun_f55e {
  strings:
    $key_f55e = { a6 31 [2] 82 3f [2] a9 13 [2] 87 31 [2] 93 2a [2] 9c 30 [2] 82 2d [2] 80 2c [2] 9b 2a [2] 87 2d [2] 9b 02 }

  condition:
    any of them
}