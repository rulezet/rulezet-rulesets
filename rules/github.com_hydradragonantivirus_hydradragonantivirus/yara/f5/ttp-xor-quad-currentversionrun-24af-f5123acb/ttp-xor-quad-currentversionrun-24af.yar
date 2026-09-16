rule TTP_XOR_QUAD_CurrentVersionRun_24af {
  strings:
    $key_24af = { 77 c0 [2] 53 ce [2] 78 e2 [2] 56 c0 [2] 42 db [2] 4d c1 [2] 53 dc [2] 51 dd [2] 4a db [2] 56 dc [2] 4a f3 }

  condition:
    any of them
}