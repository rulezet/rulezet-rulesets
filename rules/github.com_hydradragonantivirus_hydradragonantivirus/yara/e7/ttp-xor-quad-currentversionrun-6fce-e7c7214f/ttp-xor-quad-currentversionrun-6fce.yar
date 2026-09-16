rule TTP_XOR_QUAD_CurrentVersionRun_6fce {
  strings:
    $key_6fce = { 3c a1 [2] 18 af [2] 33 83 [2] 1d a1 [2] 09 ba [2] 06 a0 [2] 18 bd [2] 1a bc [2] 01 ba [2] 1d bd [2] 01 92 }

  condition:
    any of them
}