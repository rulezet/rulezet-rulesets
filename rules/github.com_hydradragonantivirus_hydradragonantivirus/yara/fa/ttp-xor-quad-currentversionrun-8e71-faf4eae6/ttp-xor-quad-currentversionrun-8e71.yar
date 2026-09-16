rule TTP_XOR_QUAD_CurrentVersionRun_8e71 {
  strings:
    $key_8e71 = { dd 1e [2] f9 10 [2] d2 3c [2] fc 1e [2] e8 05 [2] e7 1f [2] f9 02 [2] fb 03 [2] e0 05 [2] fc 02 [2] e0 2d }

  condition:
    any of them
}