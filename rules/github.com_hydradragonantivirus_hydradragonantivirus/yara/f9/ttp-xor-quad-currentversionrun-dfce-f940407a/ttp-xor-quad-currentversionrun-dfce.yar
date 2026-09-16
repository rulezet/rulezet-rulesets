rule TTP_XOR_QUAD_CurrentVersionRun_dfce {
  strings:
    $key_dfce = { 8c a1 [2] a8 af [2] 83 83 [2] ad a1 [2] b9 ba [2] b6 a0 [2] a8 bd [2] aa bc [2] b1 ba [2] ad bd [2] b1 92 }

  condition:
    any of them
}