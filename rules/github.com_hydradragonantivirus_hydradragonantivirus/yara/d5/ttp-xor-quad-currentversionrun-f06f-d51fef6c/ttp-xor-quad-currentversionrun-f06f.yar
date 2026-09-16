rule TTP_XOR_QUAD_CurrentVersionRun_f06f {
  strings:
    $key_f06f = { a3 00 [2] 87 0e [2] ac 22 [2] 82 00 [2] 96 1b [2] 99 01 [2] 87 1c [2] 85 1d [2] 9e 1b [2] 82 1c [2] 9e 33 }

  condition:
    any of them
}