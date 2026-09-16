rule TTP_XOR_QUAD_CurrentVersionRun_8d87 {
  strings:
    $key_8d87 = { de e8 [2] fa e6 [2] d1 ca [2] ff e8 [2] eb f3 [2] e4 e9 [2] fa f4 [2] f8 f5 [2] e3 f3 [2] ff f4 [2] e3 db }

  condition:
    any of them
}