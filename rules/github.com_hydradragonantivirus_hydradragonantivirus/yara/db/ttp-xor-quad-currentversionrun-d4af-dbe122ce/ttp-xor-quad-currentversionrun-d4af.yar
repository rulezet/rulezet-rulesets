rule TTP_XOR_QUAD_CurrentVersionRun_d4af {
  strings:
    $key_d4af = { 87 c0 [2] a3 ce [2] 88 e2 [2] a6 c0 [2] b2 db [2] bd c1 [2] a3 dc [2] a1 dd [2] ba db [2] a6 dc [2] ba f3 }

  condition:
    any of them
}