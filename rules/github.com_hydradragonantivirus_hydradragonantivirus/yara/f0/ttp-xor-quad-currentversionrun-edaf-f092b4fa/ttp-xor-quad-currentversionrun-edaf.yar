rule TTP_XOR_QUAD_CurrentVersionRun_edaf {
  strings:
    $key_edaf = { be c0 [2] 9a ce [2] b1 e2 [2] 9f c0 [2] 8b db [2] 84 c1 [2] 9a dc [2] 98 dd [2] 83 db [2] 9f dc [2] 83 f3 }

  condition:
    any of them
}