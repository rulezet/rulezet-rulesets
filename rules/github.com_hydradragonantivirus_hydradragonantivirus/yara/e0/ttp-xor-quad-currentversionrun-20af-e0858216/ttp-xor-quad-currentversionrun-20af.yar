rule TTP_XOR_QUAD_CurrentVersionRun_20af {
  strings:
    $key_20af = { 73 c0 [2] 57 ce [2] 7c e2 [2] 52 c0 [2] 46 db [2] 49 c1 [2] 57 dc [2] 55 dd [2] 4e db [2] 52 dc [2] 4e f3 }

  condition:
    any of them
}