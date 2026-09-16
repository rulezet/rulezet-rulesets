rule TTP_XOR_QUAD_CurrentVersionRun_e773 {
  strings:
    $key_e773 = { b4 1c [2] 90 12 [2] bb 3e [2] 95 1c [2] 81 07 [2] 8e 1d [2] 90 00 [2] 92 01 [2] 89 07 [2] 95 00 [2] 89 2f }

  condition:
    any of them
}