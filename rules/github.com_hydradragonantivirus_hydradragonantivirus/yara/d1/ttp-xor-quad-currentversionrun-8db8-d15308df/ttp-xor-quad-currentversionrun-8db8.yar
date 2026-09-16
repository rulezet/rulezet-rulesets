rule TTP_XOR_QUAD_CurrentVersionRun_8db8 {
  strings:
    $key_8db8 = { de d7 [2] fa d9 [2] d1 f5 [2] ff d7 [2] eb cc [2] e4 d6 [2] fa cb [2] f8 ca [2] e3 cc [2] ff cb [2] e3 e4 }

  condition:
    any of them
}