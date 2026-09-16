rule TTP_XOR_QUAD_CurrentVersionRun_8f99 {
  strings:
    $key_8f99 = { dc f6 [2] f8 f8 [2] d3 d4 [2] fd f6 [2] e9 ed [2] e6 f7 [2] f8 ea [2] fa eb [2] e1 ed [2] fd ea [2] e1 c5 }

  condition:
    any of them
}