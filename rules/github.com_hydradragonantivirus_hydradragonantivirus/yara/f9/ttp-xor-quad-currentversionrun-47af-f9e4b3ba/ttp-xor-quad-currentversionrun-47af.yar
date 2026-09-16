rule TTP_XOR_QUAD_CurrentVersionRun_47af {
  strings:
    $key_47af = { 14 c0 [2] 30 ce [2] 1b e2 [2] 35 c0 [2] 21 db [2] 2e c1 [2] 30 dc [2] 32 dd [2] 29 db [2] 35 dc [2] 29 f3 }

  condition:
    any of them
}