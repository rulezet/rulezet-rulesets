rule TTP_XOR_QUAD_CurrentVersionRun_94a7 {
  strings:
    $key_94a7 = { c7 c8 [2] e3 c6 [2] c8 ea [2] e6 c8 [2] f2 d3 [2] fd c9 [2] e3 d4 [2] e1 d5 [2] fa d3 [2] e6 d4 [2] fa fb }

  condition:
    any of them
}