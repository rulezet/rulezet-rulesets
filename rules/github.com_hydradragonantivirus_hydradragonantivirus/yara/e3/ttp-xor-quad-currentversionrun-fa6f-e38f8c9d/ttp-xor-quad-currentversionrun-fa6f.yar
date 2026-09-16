rule TTP_XOR_QUAD_CurrentVersionRun_fa6f {
  strings:
    $key_fa6f = { a9 00 [2] 8d 0e [2] a6 22 [2] 88 00 [2] 9c 1b [2] 93 01 [2] 8d 1c [2] 8f 1d [2] 94 1b [2] 88 1c [2] 94 33 }

  condition:
    any of them
}