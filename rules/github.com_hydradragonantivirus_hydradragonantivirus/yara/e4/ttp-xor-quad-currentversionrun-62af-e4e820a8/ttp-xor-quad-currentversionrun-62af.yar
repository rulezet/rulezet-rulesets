rule TTP_XOR_QUAD_CurrentVersionRun_62af {
  strings:
    $key_62af = { 31 c0 [2] 15 ce [2] 3e e2 [2] 10 c0 [2] 04 db [2] 0b c1 [2] 15 dc [2] 17 dd [2] 0c db [2] 10 dc [2] 0c f3 }

  condition:
    any of them
}