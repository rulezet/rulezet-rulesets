rule TTP_XOR_QUAD_CurrentVersionRun_f26f {
  strings:
    $key_f26f = { a1 00 [2] 85 0e [2] ae 22 [2] 80 00 [2] 94 1b [2] 9b 01 [2] 85 1c [2] 87 1d [2] 9c 1b [2] 80 1c [2] 9c 33 }

  condition:
    any of them
}