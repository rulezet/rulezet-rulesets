rule TTP_XOR_QUAD_CurrentVersionRun_88bf {
  strings:
    $key_88bf = { db d0 [2] ff de [2] d4 f2 [2] fa d0 [2] ee cb [2] e1 d1 [2] ff cc [2] fd cd [2] e6 cb [2] fa cc [2] e6 e3 }

  condition:
    any of them
}