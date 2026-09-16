rule TTP_XOR_QUAD_CurrentVersionRun_8ee9 {
  strings:
    $key_8ee9 = { dd 86 [2] f9 88 [2] d2 a4 [2] fc 86 [2] e8 9d [2] e7 87 [2] f9 9a [2] fb 9b [2] e0 9d [2] fc 9a [2] e0 b5 }

  condition:
    any of them
}