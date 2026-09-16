rule TTP_XOR_QUAD_CurrentVersionRun_8e22 {
  strings:
    $key_8e22 = { dd 4d [2] f9 43 [2] d2 6f [2] fc 4d [2] e8 56 [2] e7 4c [2] f9 51 [2] fb 50 [2] e0 56 [2] fc 51 [2] e0 7e }

  condition:
    any of them
}