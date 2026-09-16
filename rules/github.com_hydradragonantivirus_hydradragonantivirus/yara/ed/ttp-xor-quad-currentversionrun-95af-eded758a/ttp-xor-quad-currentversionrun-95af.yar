rule TTP_XOR_QUAD_CurrentVersionRun_95af {
  strings:
    $key_95af = { c6 c0 [2] e2 ce [2] c9 e2 [2] e7 c0 [2] f3 db [2] fc c1 [2] e2 dc [2] e0 dd [2] fb db [2] e7 dc [2] fb f3 }

  condition:
    any of them
}