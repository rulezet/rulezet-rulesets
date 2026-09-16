rule TTP_XOR_QUAD_CurrentVersionRun_8e53 {
  strings:
    $key_8e53 = { dd 3c [2] f9 32 [2] d2 1e [2] fc 3c [2] e8 27 [2] e7 3d [2] f9 20 [2] fb 21 [2] e0 27 [2] fc 20 [2] e0 0f }

  condition:
    any of them
}