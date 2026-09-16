rule TTP_XOR_QUAD_CurrentVersionRun_8e69 {
  strings:
    $key_8e69 = { dd 06 [2] f9 08 [2] d2 24 [2] fc 06 [2] e8 1d [2] e7 07 [2] f9 1a [2] fb 1b [2] e0 1d [2] fc 1a [2] e0 35 }

  condition:
    any of them
}