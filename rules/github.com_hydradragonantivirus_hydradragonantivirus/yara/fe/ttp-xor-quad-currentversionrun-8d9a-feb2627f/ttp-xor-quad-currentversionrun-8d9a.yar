rule TTP_XOR_QUAD_CurrentVersionRun_8d9a {
  strings:
    $key_8d9a = { de f5 [2] fa fb [2] d1 d7 [2] ff f5 [2] eb ee [2] e4 f4 [2] fa e9 [2] f8 e8 [2] e3 ee [2] ff e9 [2] e3 c6 }

  condition:
    any of them
}