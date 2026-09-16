rule TTP_XOR_QUAD_CurrentVersionRun_8f97 {
  strings:
    $key_8f97 = { dc f8 [2] f8 f6 [2] d3 da [2] fd f8 [2] e9 e3 [2] e6 f9 [2] f8 e4 [2] fa e5 [2] e1 e3 [2] fd e4 [2] e1 cb }

  condition:
    any of them
}