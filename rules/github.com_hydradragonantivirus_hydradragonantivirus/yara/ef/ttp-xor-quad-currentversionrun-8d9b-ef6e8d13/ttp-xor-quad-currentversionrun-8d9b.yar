rule TTP_XOR_QUAD_CurrentVersionRun_8d9b {
  strings:
    $key_8d9b = { de f4 [2] fa fa [2] d1 d6 [2] ff f4 [2] eb ef [2] e4 f5 [2] fa e8 [2] f8 e9 [2] e3 ef [2] ff e8 [2] e3 c7 }

  condition:
    any of them
}