rule TTP_XOR_QUAD_CurrentVersionRun_8e30 {
  strings:
    $key_8e30 = { dd 5f [2] f9 51 [2] d2 7d [2] fc 5f [2] e8 44 [2] e7 5e [2] f9 43 [2] fb 42 [2] e0 44 [2] fc 43 [2] e0 6c }

  condition:
    any of them
}