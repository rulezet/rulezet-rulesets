rule TTP_XOR_QUAD_CurrentVersionRun_4aaf {
  strings:
    $key_4aaf = { 19 c0 [2] 3d ce [2] 16 e2 [2] 38 c0 [2] 2c db [2] 23 c1 [2] 3d dc [2] 3f dd [2] 24 db [2] 38 dc [2] 24 f3 }

  condition:
    any of them
}