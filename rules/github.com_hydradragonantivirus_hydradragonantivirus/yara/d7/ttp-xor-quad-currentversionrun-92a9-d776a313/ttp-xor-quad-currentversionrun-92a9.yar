rule TTP_XOR_QUAD_CurrentVersionRun_92a9 {
  strings:
    $key_92a9 = { c1 c6 [2] e5 c8 [2] ce e4 [2] e0 c6 [2] f4 dd [2] fb c7 [2] e5 da [2] e7 db [2] fc dd [2] e0 da [2] fc f5 }

  condition:
    any of them
}