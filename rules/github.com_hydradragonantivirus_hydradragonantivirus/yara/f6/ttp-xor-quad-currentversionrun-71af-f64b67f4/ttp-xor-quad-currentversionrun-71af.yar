rule TTP_XOR_QUAD_CurrentVersionRun_71af {
  strings:
    $key_71af = { 22 c0 [2] 06 ce [2] 2d e2 [2] 03 c0 [2] 17 db [2] 18 c1 [2] 06 dc [2] 04 dd [2] 1f db [2] 03 dc [2] 1f f3 }

  condition:
    any of them
}