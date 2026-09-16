rule TTP_XOR_QUAD_CurrentVersionRun_55af {
  strings:
    $key_55af = { 06 c0 [2] 22 ce [2] 09 e2 [2] 27 c0 [2] 33 db [2] 3c c1 [2] 22 dc [2] 20 dd [2] 3b db [2] 27 dc [2] 3b f3 }

  condition:
    any of them
}