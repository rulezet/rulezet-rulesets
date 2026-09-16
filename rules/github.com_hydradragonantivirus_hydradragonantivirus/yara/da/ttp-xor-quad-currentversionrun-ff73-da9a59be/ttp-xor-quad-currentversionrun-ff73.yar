rule TTP_XOR_QUAD_CurrentVersionRun_ff73 {
  strings:
    $key_ff73 = { ac 1c [2] 88 12 [2] a3 3e [2] 8d 1c [2] 99 07 [2] 96 1d [2] 88 00 [2] 8a 01 [2] 91 07 [2] 8d 00 [2] 91 2f }

  condition:
    any of them
}