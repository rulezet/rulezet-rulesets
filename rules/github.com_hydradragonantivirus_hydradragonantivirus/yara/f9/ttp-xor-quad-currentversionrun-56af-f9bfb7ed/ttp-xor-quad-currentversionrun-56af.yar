rule TTP_XOR_QUAD_CurrentVersionRun_56af {
  strings:
    $key_56af = { 05 c0 [2] 21 ce [2] 0a e2 [2] 24 c0 [2] 30 db [2] 3f c1 [2] 21 dc [2] 23 dd [2] 38 db [2] 24 dc [2] 38 f3 }

  condition:
    any of them
}