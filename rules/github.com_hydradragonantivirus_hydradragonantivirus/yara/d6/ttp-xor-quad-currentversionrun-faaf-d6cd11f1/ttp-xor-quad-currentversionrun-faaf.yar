rule TTP_XOR_QUAD_CurrentVersionRun_faaf {
  strings:
    $key_faaf = { a9 c0 [2] 8d ce [2] a6 e2 [2] 88 c0 [2] 9c db [2] 93 c1 [2] 8d dc [2] 8f dd [2] 94 db [2] 88 dc [2] 94 f3 }

  condition:
    any of them
}