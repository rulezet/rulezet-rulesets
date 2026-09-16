rule TTP_XOR_QUAD_CurrentVersionRun_f46f {
  strings:
    $key_f46f = { a7 00 [2] 83 0e [2] a8 22 [2] 86 00 [2] 92 1b [2] 9d 01 [2] 83 1c [2] 81 1d [2] 9a 1b [2] 86 1c [2] 9a 33 }

  condition:
    any of them
}