rule TTP_XOR_QUAD_CurrentVersionRun_8e0d {
  strings:
    $key_8e0d = { dd 62 [2] f9 6c [2] d2 40 [2] fc 62 [2] e8 79 [2] e7 63 [2] f9 7e [2] fb 7f [2] e0 79 [2] fc 7e [2] e0 51 }

  condition:
    any of them
}