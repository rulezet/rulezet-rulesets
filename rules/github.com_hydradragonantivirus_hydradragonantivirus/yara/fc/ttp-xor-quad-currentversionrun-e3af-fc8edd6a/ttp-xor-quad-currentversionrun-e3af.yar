rule TTP_XOR_QUAD_CurrentVersionRun_e3af {
  strings:
    $key_e3af = { b0 c0 [2] 94 ce [2] bf e2 [2] 91 c0 [2] 85 db [2] 8a c1 [2] 94 dc [2] 96 dd [2] 8d db [2] 91 dc [2] 8d f3 }

  condition:
    any of them
}