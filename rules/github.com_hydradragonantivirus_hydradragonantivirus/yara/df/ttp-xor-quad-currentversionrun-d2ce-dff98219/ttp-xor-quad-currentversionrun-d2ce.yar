rule TTP_XOR_QUAD_CurrentVersionRun_d2ce {
  strings:
    $key_d2ce = { 81 a1 [2] a5 af [2] 8e 83 [2] a0 a1 [2] b4 ba [2] bb a0 [2] a5 bd [2] a7 bc [2] bc ba [2] a0 bd [2] bc 92 }

  condition:
    any of them
}