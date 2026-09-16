rule TTP_XOR_QUAD_CurrentVersionRun_8e3e {
  strings:
    $key_8e3e = { dd 51 [2] f9 5f [2] d2 73 [2] fc 51 [2] e8 4a [2] e7 50 [2] f9 4d [2] fb 4c [2] e0 4a [2] fc 4d [2] e0 62 }

  condition:
    any of them
}