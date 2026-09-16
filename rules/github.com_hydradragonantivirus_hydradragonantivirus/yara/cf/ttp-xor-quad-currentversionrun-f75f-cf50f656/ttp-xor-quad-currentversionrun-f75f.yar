rule TTP_XOR_QUAD_CurrentVersionRun_f75f {
  strings:
    $key_f75f = { a4 30 [2] 80 3e [2] ab 12 [2] 85 30 [2] 91 2b [2] 9e 31 [2] 80 2c [2] 82 2d [2] 99 2b [2] 85 2c [2] 99 03 }

  condition:
    any of them
}