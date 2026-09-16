rule TTP_XOR_QUAD_CurrentVersionRun_8eed {
  strings:
    $key_8eed = { dd 82 [2] f9 8c [2] d2 a0 [2] fc 82 [2] e8 99 [2] e7 83 [2] f9 9e [2] fb 9f [2] e0 99 [2] fc 9e [2] e0 b1 }

  condition:
    any of them
}