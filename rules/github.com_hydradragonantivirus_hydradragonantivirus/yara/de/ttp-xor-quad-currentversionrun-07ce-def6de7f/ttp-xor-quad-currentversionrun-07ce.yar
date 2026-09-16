rule TTP_XOR_QUAD_CurrentVersionRun_07ce {
  strings:
    $key_07ce = { 54 a1 [2] 70 af [2] 5b 83 [2] 75 a1 [2] 61 ba [2] 6e a0 [2] 70 bd [2] 72 bc [2] 69 ba [2] 75 bd [2] 69 92 }

  condition:
    any of them
}