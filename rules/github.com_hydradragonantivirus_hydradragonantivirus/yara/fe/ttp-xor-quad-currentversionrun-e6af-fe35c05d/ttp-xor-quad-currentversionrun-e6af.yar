rule TTP_XOR_QUAD_CurrentVersionRun_e6af {
  strings:
    $key_e6af = { b5 c0 [2] 91 ce [2] ba e2 [2] 94 c0 [2] 80 db [2] 8f c1 [2] 91 dc [2] 93 dd [2] 88 db [2] 94 dc [2] 88 f3 }

  condition:
    any of them
}