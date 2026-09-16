rule TTP_XOR_QUAD_CurrentVersionRun_efce {
  strings:
    $key_efce = { bc a1 [2] 98 af [2] b3 83 [2] 9d a1 [2] 89 ba [2] 86 a0 [2] 98 bd [2] 9a bc [2] 81 ba [2] 9d bd [2] 81 92 }

  condition:
    any of them
}