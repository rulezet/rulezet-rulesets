rule TTP_XOR_QUAD_CurrentVersionRun_8ef4 {
  strings:
    $key_8ef4 = { dd 9b [2] f9 95 [2] d2 b9 [2] fc 9b [2] e8 80 [2] e7 9a [2] f9 87 [2] fb 86 [2] e0 80 [2] fc 87 [2] e0 a8 }

  condition:
    any of them
}