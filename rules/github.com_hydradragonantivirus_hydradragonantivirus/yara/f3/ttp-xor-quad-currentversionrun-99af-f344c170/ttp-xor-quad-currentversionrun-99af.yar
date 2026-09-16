rule TTP_XOR_QUAD_CurrentVersionRun_99af {
  strings:
    $key_99af = { ca c0 [2] ee ce [2] c5 e2 [2] eb c0 [2] ff db [2] f0 c1 [2] ee dc [2] ec dd [2] f7 db [2] eb dc [2] f7 f3 }

  condition:
    any of them
}