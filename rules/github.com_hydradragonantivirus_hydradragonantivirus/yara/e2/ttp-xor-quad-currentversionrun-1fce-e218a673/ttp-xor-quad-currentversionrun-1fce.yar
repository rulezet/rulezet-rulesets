rule TTP_XOR_QUAD_CurrentVersionRun_1fce {
  strings:
    $key_1fce = { 4c a1 [2] 68 af [2] 43 83 [2] 6d a1 [2] 79 ba [2] 76 a0 [2] 68 bd [2] 6a bc [2] 71 ba [2] 6d bd [2] 71 92 }

  condition:
    any of them
}