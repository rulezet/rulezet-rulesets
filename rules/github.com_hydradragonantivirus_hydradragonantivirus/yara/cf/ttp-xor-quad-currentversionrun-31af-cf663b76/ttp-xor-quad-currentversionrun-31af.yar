rule TTP_XOR_QUAD_CurrentVersionRun_31af {
  strings:
    $key_31af = { 62 c0 [2] 46 ce [2] 6d e2 [2] 43 c0 [2] 57 db [2] 58 c1 [2] 46 dc [2] 44 dd [2] 5f db [2] 43 dc [2] 5f f3 }

  condition:
    any of them
}