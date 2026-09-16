rule TTP_XOR_QUAD_CurrentVersionRun_17af {
  strings:
    $key_17af = { 44 c0 [2] 60 ce [2] 4b e2 [2] 65 c0 [2] 71 db [2] 7e c1 [2] 60 dc [2] 62 dd [2] 79 db [2] 65 dc [2] 79 f3 }

  condition:
    any of them
}