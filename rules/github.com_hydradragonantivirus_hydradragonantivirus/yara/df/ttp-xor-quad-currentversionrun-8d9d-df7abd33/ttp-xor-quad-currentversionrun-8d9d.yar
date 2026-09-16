rule TTP_XOR_QUAD_CurrentVersionRun_8d9d {
  strings:
    $key_8d9d = { de f2 [2] fa fc [2] d1 d0 [2] ff f2 [2] eb e9 [2] e4 f3 [2] fa ee [2] f8 ef [2] e3 e9 [2] ff ee [2] e3 c1 }

  condition:
    any of them
}