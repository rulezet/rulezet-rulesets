rule TTP_XOR_QUAD_CurrentVersionRun_1faf {
  strings:
    $key_1faf = { 4c c0 [2] 68 ce [2] 43 e2 [2] 6d c0 [2] 79 db [2] 76 c1 [2] 68 dc [2] 6a dd [2] 71 db [2] 6d dc [2] 71 f3 }

  condition:
    any of them
}