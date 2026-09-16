rule TTP_XOR_QUAD_CurrentVersionRun_7eaf {
  strings:
    $key_7eaf = { 2d c0 [2] 09 ce [2] 22 e2 [2] 0c c0 [2] 18 db [2] 17 c1 [2] 09 dc [2] 0b dd [2] 10 db [2] 0c dc [2] 10 f3 }

  condition:
    any of them
}