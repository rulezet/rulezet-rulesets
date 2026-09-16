rule TTP_XOR_QUAD_CurrentVersionRun_8e08 {
  strings:
    $key_8e08 = { dd 67 [2] f9 69 [2] d2 45 [2] fc 67 [2] e8 7c [2] e7 66 [2] f9 7b [2] fb 7a [2] e0 7c [2] fc 7b [2] e0 54 }

  condition:
    any of them
}