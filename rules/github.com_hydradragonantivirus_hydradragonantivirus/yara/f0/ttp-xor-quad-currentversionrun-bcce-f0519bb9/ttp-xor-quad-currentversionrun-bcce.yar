rule TTP_XOR_QUAD_CurrentVersionRun_bcce {
  strings:
    $key_bcce = { ef a1 [2] cb af [2] e0 83 [2] ce a1 [2] da ba [2] d5 a0 [2] cb bd [2] c9 bc [2] d2 ba [2] ce bd [2] d2 92 }

  condition:
    any of them
}