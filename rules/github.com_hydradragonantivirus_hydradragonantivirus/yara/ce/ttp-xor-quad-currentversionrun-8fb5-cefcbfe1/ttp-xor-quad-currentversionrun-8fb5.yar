rule TTP_XOR_QUAD_CurrentVersionRun_8fb5 {
  strings:
    $key_8fb5 = { dc da [2] f8 d4 [2] d3 f8 [2] fd da [2] e9 c1 [2] e6 db [2] f8 c6 [2] fa c7 [2] e1 c1 [2] fd c6 [2] e1 e9 }

  condition:
    any of them
}