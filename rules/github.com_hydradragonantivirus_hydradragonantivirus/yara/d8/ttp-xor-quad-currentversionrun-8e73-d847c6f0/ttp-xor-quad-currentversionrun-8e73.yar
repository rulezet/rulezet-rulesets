rule TTP_XOR_QUAD_CurrentVersionRun_8e73 {
  strings:
    $key_8e73 = { dd 1c [2] f9 12 [2] d2 3e [2] fc 1c [2] e8 07 [2] e7 1d [2] f9 00 [2] fb 01 [2] e0 07 [2] fc 00 [2] e0 2f }

  condition:
    any of them
}