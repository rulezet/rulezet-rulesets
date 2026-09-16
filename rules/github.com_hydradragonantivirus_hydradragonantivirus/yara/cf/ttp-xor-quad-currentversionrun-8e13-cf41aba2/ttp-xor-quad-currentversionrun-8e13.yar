rule TTP_XOR_QUAD_CurrentVersionRun_8e13 {
  strings:
    $key_8e13 = { dd 7c [2] f9 72 [2] d2 5e [2] fc 7c [2] e8 67 [2] e7 7d [2] f9 60 [2] fb 61 [2] e0 67 [2] fc 60 [2] e0 4f }

  condition:
    any of them
}