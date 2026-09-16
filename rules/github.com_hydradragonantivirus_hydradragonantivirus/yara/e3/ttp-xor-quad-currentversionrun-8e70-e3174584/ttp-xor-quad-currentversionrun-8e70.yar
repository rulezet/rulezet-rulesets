rule TTP_XOR_QUAD_CurrentVersionRun_8e70 {
  strings:
    $key_8e70 = { dd 1f [2] f9 11 [2] d2 3d [2] fc 1f [2] e8 04 [2] e7 1e [2] f9 03 [2] fb 02 [2] e0 04 [2] fc 03 [2] e0 2c }

  condition:
    any of them
}