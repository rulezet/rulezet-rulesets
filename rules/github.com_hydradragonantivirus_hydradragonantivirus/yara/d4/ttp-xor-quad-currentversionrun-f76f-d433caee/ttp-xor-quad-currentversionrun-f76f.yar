rule TTP_XOR_QUAD_CurrentVersionRun_f76f {
  strings:
    $key_f76f = { a4 00 [2] 80 0e [2] ab 22 [2] 85 00 [2] 91 1b [2] 9e 01 [2] 80 1c [2] 82 1d [2] 99 1b [2] 85 1c [2] 99 33 }

  condition:
    any of them
}