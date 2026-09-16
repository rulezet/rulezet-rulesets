rule TTP_XOR_QUAD_CurrentVersionRun_04ce {
  strings:
    $key_04ce = { 57 a1 [2] 73 af [2] 58 83 [2] 76 a1 [2] 62 ba [2] 6d a0 [2] 73 bd [2] 71 bc [2] 6a ba [2] 76 bd [2] 6a 92 }

  condition:
    any of them
}