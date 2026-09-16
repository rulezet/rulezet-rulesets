rule TTP_XOR_QUAD_CurrentVersionRun_8e79 {
  strings:
    $key_8e79 = { dd 16 [2] f9 18 [2] d2 34 [2] fc 16 [2] e8 0d [2] e7 17 [2] f9 0a [2] fb 0b [2] e0 0d [2] fc 0a [2] e0 25 }

  condition:
    any of them
}