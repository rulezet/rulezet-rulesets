rule TTP_XOR_QUAD_CurrentVersionRun_8d96 {
  strings:
    $key_8d96 = { de f9 [2] fa f7 [2] d1 db [2] ff f9 [2] eb e2 [2] e4 f8 [2] fa e5 [2] f8 e4 [2] e3 e2 [2] ff e5 [2] e3 ca }

  condition:
    any of them
}