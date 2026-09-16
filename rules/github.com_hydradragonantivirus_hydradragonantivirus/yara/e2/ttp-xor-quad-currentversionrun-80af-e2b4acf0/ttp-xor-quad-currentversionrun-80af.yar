rule TTP_XOR_QUAD_CurrentVersionRun_80af {
  strings:
    $key_80af = { d3 c0 [2] f7 ce [2] dc e2 [2] f2 c0 [2] e6 db [2] e9 c1 [2] f7 dc [2] f5 dd [2] ee db [2] f2 dc [2] ee f3 }

  condition:
    any of them
}