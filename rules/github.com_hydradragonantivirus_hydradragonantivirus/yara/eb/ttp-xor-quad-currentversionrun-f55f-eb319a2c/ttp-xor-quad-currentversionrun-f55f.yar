rule TTP_XOR_QUAD_CurrentVersionRun_f55f {
  strings:
    $key_f55f = { a6 30 [2] 82 3e [2] a9 12 [2] 87 30 [2] 93 2b [2] 9c 31 [2] 82 2c [2] 80 2d [2] 9b 2b [2] 87 2c [2] 9b 03 }

  condition:
    any of them
}