rule TTP_XOR_QUAD_CurrentVersionRun_8ef6 {
  strings:
    $key_8ef6 = { dd 99 [2] f9 97 [2] d2 bb [2] fc 99 [2] e8 82 [2] e7 98 [2] f9 85 [2] fb 84 [2] e0 82 [2] fc 85 [2] e0 aa }

  condition:
    any of them
}