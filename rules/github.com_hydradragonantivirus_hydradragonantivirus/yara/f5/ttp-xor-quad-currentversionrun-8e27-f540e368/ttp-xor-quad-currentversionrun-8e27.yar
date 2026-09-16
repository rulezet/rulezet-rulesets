rule TTP_XOR_QUAD_CurrentVersionRun_8e27 {
  strings:
    $key_8e27 = { dd 48 [2] f9 46 [2] d2 6a [2] fc 48 [2] e8 53 [2] e7 49 [2] f9 54 [2] fb 55 [2] e0 53 [2] fc 54 [2] e0 7b }

  condition:
    any of them
}