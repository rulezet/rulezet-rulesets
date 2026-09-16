rule TTP_XOR_QUAD_CurrentVersionRun_36af {
  strings:
    $key_36af = { 65 c0 [2] 41 ce [2] 6a e2 [2] 44 c0 [2] 50 db [2] 5f c1 [2] 41 dc [2] 43 dd [2] 58 db [2] 44 dc [2] 58 f3 }

  condition:
    any of them
}