rule TTP_XOR_QUAD_CurrentVersionRun_bfce {
  strings:
    $key_bfce = { ec a1 [2] c8 af [2] e3 83 [2] cd a1 [2] d9 ba [2] d6 a0 [2] c8 bd [2] ca bc [2] d1 ba [2] cd bd [2] d1 92 }

  condition:
    any of them
}