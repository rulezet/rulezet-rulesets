rule TTP_XOR_QUAD_CurrentVersionRun_94ba {
  strings:
    $key_94ba = { c7 d5 [2] e3 db [2] c8 f7 [2] e6 d5 [2] f2 ce [2] fd d4 [2] e3 c9 [2] e1 c8 [2] fa ce [2] e6 c9 [2] fa e6 }

  condition:
    any of them
}