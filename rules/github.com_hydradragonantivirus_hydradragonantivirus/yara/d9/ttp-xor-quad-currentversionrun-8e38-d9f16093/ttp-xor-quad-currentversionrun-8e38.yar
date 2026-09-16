rule TTP_XOR_QUAD_CurrentVersionRun_8e38 {
  strings:
    $key_8e38 = { dd 57 [2] f9 59 [2] d2 75 [2] fc 57 [2] e8 4c [2] e7 56 [2] f9 4b [2] fb 4a [2] e0 4c [2] fc 4b [2] e0 64 }

  condition:
    any of them
}