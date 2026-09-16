rule TTP_XOR_QUAD_CurrentVersionRun_8efd {
  strings:
    $key_8efd = { dd 92 [2] f9 9c [2] d2 b0 [2] fc 92 [2] e8 89 [2] e7 93 [2] f9 8e [2] fb 8f [2] e0 89 [2] fc 8e [2] e0 a1 }

  condition:
    any of them
}