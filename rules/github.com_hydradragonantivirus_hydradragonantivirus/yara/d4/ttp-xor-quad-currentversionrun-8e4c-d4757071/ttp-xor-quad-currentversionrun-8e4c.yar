rule TTP_XOR_QUAD_CurrentVersionRun_8e4c {
  strings:
    $key_8e4c = { dd 23 [2] f9 2d [2] d2 01 [2] fc 23 [2] e8 38 [2] e7 22 [2] f9 3f [2] fb 3e [2] e0 38 [2] fc 3f [2] e0 10 }

  condition:
    any of them
}