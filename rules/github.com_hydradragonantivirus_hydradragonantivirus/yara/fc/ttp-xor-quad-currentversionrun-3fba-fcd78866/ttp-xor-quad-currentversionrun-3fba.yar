rule TTP_XOR_QUAD_CurrentVersionRun_3fba {
  strings:
    $key_3fba = { 6c d5 [2] 48 db [2] 63 f7 [2] 4d d5 [2] 59 ce [2] 56 d4 [2] 48 c9 [2] 4a c8 [2] 51 ce [2] 4d c9 [2] 51 e6 }

  condition:
    any of them
}