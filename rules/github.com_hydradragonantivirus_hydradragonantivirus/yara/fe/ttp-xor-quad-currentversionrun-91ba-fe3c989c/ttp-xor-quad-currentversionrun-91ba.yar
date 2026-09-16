rule TTP_XOR_QUAD_CurrentVersionRun_91ba {
  strings:
    $key_91ba = { c2 d5 [2] e6 db [2] cd f7 [2] e3 d5 [2] f7 ce [2] f8 d4 [2] e6 c9 [2] e4 c8 [2] ff ce [2] e3 c9 [2] ff e6 }

  condition:
    any of them
}