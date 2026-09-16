rule TTP_XOR_QUAD_CurrentVersionRun_b4ce {
  strings:
    $key_b4ce = { e7 a1 [2] c3 af [2] e8 83 [2] c6 a1 [2] d2 ba [2] dd a0 [2] c3 bd [2] c1 bc [2] da ba [2] c6 bd [2] da 92 }

  condition:
    any of them
}