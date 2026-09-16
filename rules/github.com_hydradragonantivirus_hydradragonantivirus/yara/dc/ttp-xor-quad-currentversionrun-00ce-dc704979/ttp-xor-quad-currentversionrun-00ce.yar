rule TTP_XOR_QUAD_CurrentVersionRun_00ce {
  strings:
    $key_00ce = { 53 a1 [2] 77 af [2] 5c 83 [2] 72 a1 [2] 66 ba [2] 69 a0 [2] 77 bd [2] 75 bc [2] 6e ba [2] 72 bd [2] 6e 92 }

  condition:
    any of them
}