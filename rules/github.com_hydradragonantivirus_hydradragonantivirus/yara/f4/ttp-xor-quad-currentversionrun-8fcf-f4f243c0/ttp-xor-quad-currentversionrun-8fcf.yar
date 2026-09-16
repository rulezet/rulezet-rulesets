rule TTP_XOR_QUAD_CurrentVersionRun_8fcf {
  strings:
    $key_8fcf = { dc a0 [2] f8 ae [2] d3 82 [2] fd a0 [2] e9 bb [2] e6 a1 [2] f8 bc [2] fa bd [2] e1 bb [2] fd bc [2] e1 93 }

  condition:
    any of them
}