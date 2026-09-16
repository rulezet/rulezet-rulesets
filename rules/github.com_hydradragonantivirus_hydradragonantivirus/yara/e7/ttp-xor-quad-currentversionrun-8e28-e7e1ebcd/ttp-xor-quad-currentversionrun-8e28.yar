rule TTP_XOR_QUAD_CurrentVersionRun_8e28 {
  strings:
    $key_8e28 = { dd 47 [2] f9 49 [2] d2 65 [2] fc 47 [2] e8 5c [2] e7 46 [2] f9 5b [2] fb 5a [2] e0 5c [2] fc 5b [2] e0 74 }

  condition:
    any of them
}