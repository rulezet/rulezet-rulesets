rule TTP_XOR_QUAD_CurrentVersionRun_8fc7 {
  strings:
    $key_8fc7 = { dc a8 [2] f8 a6 [2] d3 8a [2] fd a8 [2] e9 b3 [2] e6 a9 [2] f8 b4 [2] fa b5 [2] e1 b3 [2] fd b4 [2] e1 9b }

  condition:
    any of them
}