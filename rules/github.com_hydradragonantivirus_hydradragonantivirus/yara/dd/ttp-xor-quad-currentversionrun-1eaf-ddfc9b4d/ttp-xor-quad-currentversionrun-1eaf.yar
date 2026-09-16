rule TTP_XOR_QUAD_CurrentVersionRun_1eaf {
  strings:
    $key_1eaf = { 4d c0 [2] 69 ce [2] 42 e2 [2] 6c c0 [2] 78 db [2] 77 c1 [2] 69 dc [2] 6b dd [2] 70 db [2] 6c dc [2] 70 f3 }

  condition:
    any of them
}