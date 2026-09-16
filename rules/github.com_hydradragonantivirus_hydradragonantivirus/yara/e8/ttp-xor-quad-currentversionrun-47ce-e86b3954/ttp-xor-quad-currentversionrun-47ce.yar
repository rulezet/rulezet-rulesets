rule TTP_XOR_QUAD_CurrentVersionRun_47ce {
  strings:
    $key_47ce = { 14 a1 [2] 30 af [2] 1b 83 [2] 35 a1 [2] 21 ba [2] 2e a0 [2] 30 bd [2] 32 bc [2] 29 ba [2] 35 bd [2] 29 92 }

  condition:
    any of them
}