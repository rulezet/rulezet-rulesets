rule TTP_XOR_QUAD_CurrentVersionRun_f773 {
  strings:
    $key_f773 = { a4 1c [2] 80 12 [2] ab 3e [2] 85 1c [2] 91 07 [2] 9e 1d [2] 80 00 [2] 82 01 [2] 99 07 [2] 85 00 [2] 99 2f }

  condition:
    any of them
}