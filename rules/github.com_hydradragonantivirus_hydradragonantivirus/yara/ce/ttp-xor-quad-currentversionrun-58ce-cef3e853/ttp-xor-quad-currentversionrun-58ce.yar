rule TTP_XOR_QUAD_CurrentVersionRun_58ce {
  strings:
    $key_58ce = { 0b a1 [2] 2f af [2] 04 83 [2] 2a a1 [2] 3e ba [2] 31 a0 [2] 2f bd [2] 2d bc [2] 36 ba [2] 2a bd [2] 36 92 }

  condition:
    any of them
}