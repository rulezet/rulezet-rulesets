rule TTP_XOR_QUAD_CurrentVersionRun_27af {
  strings:
    $key_27af = { 74 c0 [2] 50 ce [2] 7b e2 [2] 55 c0 [2] 41 db [2] 4e c1 [2] 50 dc [2] 52 dd [2] 49 db [2] 55 dc [2] 49 f3 }

  condition:
    any of them
}