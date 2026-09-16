rule TTP_XOR_QUAD_CurrentVersionRun_18ce {
  strings:
    $key_18ce = { 4b a1 [2] 6f af [2] 44 83 [2] 6a a1 [2] 7e ba [2] 71 a0 [2] 6f bd [2] 6d bc [2] 76 ba [2] 6a bd [2] 76 92 }

  condition:
    any of them
}