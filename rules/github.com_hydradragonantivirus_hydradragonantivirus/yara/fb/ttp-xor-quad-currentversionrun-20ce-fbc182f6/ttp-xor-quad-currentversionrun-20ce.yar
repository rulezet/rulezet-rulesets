rule TTP_XOR_QUAD_CurrentVersionRun_20ce {
  strings:
    $key_20ce = { 73 a1 [2] 57 af [2] 7c 83 [2] 52 a1 [2] 46 ba [2] 49 a0 [2] 57 bd [2] 55 bc [2] 4e ba [2] 52 bd [2] 4e 92 }

  condition:
    any of them
}