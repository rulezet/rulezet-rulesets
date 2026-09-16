rule TTP_XOR_QUAD_CurrentVersionRun_a9af {
  strings:
    $key_a9af = { fa c0 [2] de ce [2] f5 e2 [2] db c0 [2] cf db [2] c0 c1 [2] de dc [2] dc dd [2] c7 db [2] db dc [2] c7 f3 }

  condition:
    any of them
}