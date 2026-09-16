rule TTP_XOR_QUAD_CurrentVersionRun_88b6 {
  strings:
    $key_88b6 = { db d9 [2] ff d7 [2] d4 fb [2] fa d9 [2] ee c2 [2] e1 d8 [2] ff c5 [2] fd c4 [2] e6 c2 [2] fa c5 [2] e6 ea }

  condition:
    any of them
}