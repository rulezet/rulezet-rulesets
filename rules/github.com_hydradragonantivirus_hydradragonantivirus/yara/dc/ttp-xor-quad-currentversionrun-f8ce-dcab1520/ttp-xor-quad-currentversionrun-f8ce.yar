rule TTP_XOR_QUAD_CurrentVersionRun_f8ce {
  strings:
    $key_f8ce = { ab a1 [2] 8f af [2] a4 83 [2] 8a a1 [2] 9e ba [2] 91 a0 [2] 8f bd [2] 8d bc [2] 96 ba [2] 8a bd [2] 96 92 }

  condition:
    any of them
}