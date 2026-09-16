rule TTP_XOR_QUAD_CurrentVersionRun_00af {
  strings:
    $key_00af = { 53 c0 [2] 77 ce [2] 5c e2 [2] 72 c0 [2] 66 db [2] 69 c1 [2] 77 dc [2] 75 dd [2] 6e db [2] 72 dc [2] 6e f3 }

  condition:
    any of them
}