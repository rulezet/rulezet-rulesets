rule TTP_XOR_QUAD_CurrentVersionRun_1daf {
  strings:
    $key_1daf = { 4e c0 [2] 6a ce [2] 41 e2 [2] 6f c0 [2] 7b db [2] 74 c1 [2] 6a dc [2] 68 dd [2] 73 db [2] 6f dc [2] 73 f3 }

  condition:
    any of them
}