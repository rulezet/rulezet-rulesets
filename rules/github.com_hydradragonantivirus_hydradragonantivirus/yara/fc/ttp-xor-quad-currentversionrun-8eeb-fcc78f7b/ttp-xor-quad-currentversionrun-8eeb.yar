rule TTP_XOR_QUAD_CurrentVersionRun_8eeb {
  strings:
    $key_8eeb = { dd 84 [2] f9 8a [2] d2 a6 [2] fc 84 [2] e8 9f [2] e7 85 [2] f9 98 [2] fb 99 [2] e0 9f [2] fc 98 [2] e0 b7 }

  condition:
    any of them
}