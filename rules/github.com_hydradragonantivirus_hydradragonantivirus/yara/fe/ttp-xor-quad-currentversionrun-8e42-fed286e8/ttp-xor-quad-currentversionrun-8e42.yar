rule TTP_XOR_QUAD_CurrentVersionRun_8e42 {
  strings:
    $key_8e42 = { dd 2d [2] f9 23 [2] d2 0f [2] fc 2d [2] e8 36 [2] e7 2c [2] f9 31 [2] fb 30 [2] e0 36 [2] fc 31 [2] e0 1e }

  condition:
    any of them
}