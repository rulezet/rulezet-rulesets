rule TTP_XOR_QUAD_CurrentVersionRun_41ce {
  strings:
    $key_41ce = { 12 a1 [2] 36 af [2] 1d 83 [2] 33 a1 [2] 27 ba [2] 28 a0 [2] 36 bd [2] 34 bc [2] 2f ba [2] 33 bd [2] 2f 92 }

  condition:
    any of them
}