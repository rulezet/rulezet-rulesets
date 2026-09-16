rule TTP_XOR_QUAD_CurrentVersionRun_6faf {
  strings:
    $key_6faf = { 3c c0 [2] 18 ce [2] 33 e2 [2] 1d c0 [2] 09 db [2] 06 c1 [2] 18 dc [2] 1a dd [2] 01 db [2] 1d dc [2] 01 f3 }

  condition:
    any of them
}