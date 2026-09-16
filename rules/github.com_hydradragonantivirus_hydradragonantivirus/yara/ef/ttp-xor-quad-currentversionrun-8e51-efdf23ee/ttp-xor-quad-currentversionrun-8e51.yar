rule TTP_XOR_QUAD_CurrentVersionRun_8e51 {
  strings:
    $key_8e51 = { dd 3e [2] f9 30 [2] d2 1c [2] fc 3e [2] e8 25 [2] e7 3f [2] f9 22 [2] fb 23 [2] e0 25 [2] fc 22 [2] e0 0d }

  condition:
    any of them
}