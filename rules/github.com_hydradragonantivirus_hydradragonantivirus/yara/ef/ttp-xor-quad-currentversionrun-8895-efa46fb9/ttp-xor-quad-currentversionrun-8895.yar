rule TTP_XOR_QUAD_CurrentVersionRun_8895 {
  strings:
    $key_8895 = { db fa [2] ff f4 [2] d4 d8 [2] fa fa [2] ee e1 [2] e1 fb [2] ff e6 [2] fd e7 [2] e6 e1 [2] fa e6 [2] e6 c9 }

  condition:
    any of them
}