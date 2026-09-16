rule TTP_XOR_QUAD_CurrentVersionRun_66af {
  strings:
    $key_66af = { 35 c0 [2] 11 ce [2] 3a e2 [2] 14 c0 [2] 00 db [2] 0f c1 [2] 11 dc [2] 13 dd [2] 08 db [2] 14 dc [2] 08 f3 }

  condition:
    any of them
}