rule TTP_XOR_QUAD_CurrentVersionRun_01af {
  strings:
    $key_01af = { 52 c0 [2] 76 ce [2] 5d e2 [2] 73 c0 [2] 67 db [2] 68 c1 [2] 76 dc [2] 74 dd [2] 6f db [2] 73 dc [2] 6f f3 }

  condition:
    any of them
}