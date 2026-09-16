rule TTP_XOR_QUAD_CurrentVersionRun_8e34 {
  strings:
    $key_8e34 = { dd 5b [2] f9 55 [2] d2 79 [2] fc 5b [2] e8 40 [2] e7 5a [2] f9 47 [2] fb 46 [2] e0 40 [2] fc 47 [2] e0 68 }

  condition:
    any of them
}