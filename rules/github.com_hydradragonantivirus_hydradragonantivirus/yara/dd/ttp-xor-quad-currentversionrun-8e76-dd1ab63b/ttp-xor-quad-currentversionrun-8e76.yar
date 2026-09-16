rule TTP_XOR_QUAD_CurrentVersionRun_8e76 {
  strings:
    $key_8e76 = { dd 19 [2] f9 17 [2] d2 3b [2] fc 19 [2] e8 02 [2] e7 18 [2] f9 05 [2] fb 04 [2] e0 02 [2] fc 05 [2] e0 2a }

  condition:
    any of them
}