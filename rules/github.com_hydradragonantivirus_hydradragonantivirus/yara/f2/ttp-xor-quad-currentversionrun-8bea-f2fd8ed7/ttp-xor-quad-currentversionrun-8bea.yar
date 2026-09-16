rule TTP_XOR_QUAD_CurrentVersionRun_8bea {
  strings:
    $key_8bea = { d8 85 [2] fc 8b [2] d7 a7 [2] f9 85 [2] ed 9e [2] e2 84 [2] fc 99 [2] fe 98 [2] e5 9e [2] f9 99 [2] e5 b6 }

  condition:
    any of them
}