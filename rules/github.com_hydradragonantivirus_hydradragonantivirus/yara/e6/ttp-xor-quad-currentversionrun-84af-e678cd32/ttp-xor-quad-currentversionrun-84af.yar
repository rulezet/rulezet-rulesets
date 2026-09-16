rule TTP_XOR_QUAD_CurrentVersionRun_84af {
  strings:
    $key_84af = { d7 c0 [2] f3 ce [2] d8 e2 [2] f6 c0 [2] e2 db [2] ed c1 [2] f3 dc [2] f1 dd [2] ea db [2] f6 dc [2] ea f3 }

  condition:
    any of them
}