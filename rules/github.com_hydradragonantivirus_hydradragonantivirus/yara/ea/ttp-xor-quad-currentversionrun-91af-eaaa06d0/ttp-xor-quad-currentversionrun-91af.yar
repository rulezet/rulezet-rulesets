rule TTP_XOR_QUAD_CurrentVersionRun_91af {
  strings:
    $key_91af = { c2 c0 [2] e6 ce [2] cd e2 [2] e3 c0 [2] f7 db [2] f8 c1 [2] e6 dc [2] e4 dd [2] ff db [2] e3 dc [2] ff f3 }

  condition:
    any of them
}