rule TTP_XOR_QUAD_CurrentVersionRun_fcce {
  strings:
    $key_fcce = { af a1 [2] 8b af [2] a0 83 [2] 8e a1 [2] 9a ba [2] 95 a0 [2] 8b bd [2] 89 bc [2] 92 ba [2] 8e bd [2] 92 92 }

  condition:
    any of them
}