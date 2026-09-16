rule TTP_XOR_QUAD_CurrentVersionRun_8e39 {
  strings:
    $key_8e39 = { dd 56 [2] f9 58 [2] d2 74 [2] fc 56 [2] e8 4d [2] e7 57 [2] f9 4a [2] fb 4b [2] e0 4d [2] fc 4a [2] e0 65 }

  condition:
    any of them
}