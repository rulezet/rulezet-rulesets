rule TTP_XOR_QUAD_CurrentVersionRun_7faf {
  strings:
    $key_7faf = { 2c c0 [2] 08 ce [2] 23 e2 [2] 0d c0 [2] 19 db [2] 16 c1 [2] 08 dc [2] 0a dd [2] 11 db [2] 0d dc [2] 11 f3 }

  condition:
    any of them
}