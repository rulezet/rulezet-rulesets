rule TTP_XOR_QUAD_CurrentVersionRun_8ec7 {
  strings:
    $key_8ec7 = { dd a8 [2] f9 a6 [2] d2 8a [2] fc a8 [2] e8 b3 [2] e7 a9 [2] f9 b4 [2] fb b5 [2] e0 b3 [2] fc b4 [2] e0 9b }

  condition:
    any of them
}