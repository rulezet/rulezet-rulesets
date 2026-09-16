rule TTP_XOR_QUAD_CurrentVersionRun_8e57 {
  strings:
    $key_8e57 = { dd 38 [2] f9 36 [2] d2 1a [2] fc 38 [2] e8 23 [2] e7 39 [2] f9 24 [2] fb 25 [2] e0 23 [2] fc 24 [2] e0 0b }

  condition:
    any of them
}