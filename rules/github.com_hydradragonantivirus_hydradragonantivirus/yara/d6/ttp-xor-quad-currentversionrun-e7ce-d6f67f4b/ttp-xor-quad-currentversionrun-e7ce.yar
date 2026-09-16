rule TTP_XOR_QUAD_CurrentVersionRun_e7ce {
  strings:
    $key_e7ce = { b4 a1 [2] 90 af [2] bb 83 [2] 95 a1 [2] 81 ba [2] 8e a0 [2] 90 bd [2] 92 bc [2] 89 ba [2] 95 bd [2] 89 92 }

  condition:
    any of them
}