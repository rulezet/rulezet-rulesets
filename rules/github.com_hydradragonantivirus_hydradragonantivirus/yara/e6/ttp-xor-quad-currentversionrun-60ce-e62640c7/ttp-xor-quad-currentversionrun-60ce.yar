rule TTP_XOR_QUAD_CurrentVersionRun_60ce {
  strings:
    $key_60ce = { 33 a1 [2] 17 af [2] 3c 83 [2] 12 a1 [2] 06 ba [2] 09 a0 [2] 17 bd [2] 15 bc [2] 0e ba [2] 12 bd [2] 0e 92 }

  condition:
    any of them
}