rule TTP_XOR_QUAD_CurrentVersionRun_0fce {
  strings:
    $key_0fce = { 5c a1 [2] 78 af [2] 53 83 [2] 7d a1 [2] 69 ba [2] 66 a0 [2] 78 bd [2] 7a bc [2] 61 ba [2] 7d bd [2] 61 92 }

  condition:
    any of them
}