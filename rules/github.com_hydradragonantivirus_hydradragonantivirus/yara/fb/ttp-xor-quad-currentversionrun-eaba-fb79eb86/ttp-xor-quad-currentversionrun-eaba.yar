rule TTP_XOR_QUAD_CurrentVersionRun_eaba {
  strings:
    $key_eaba = { b9 d5 [2] 9d db [2] b6 f7 [2] 98 d5 [2] 8c ce [2] 83 d4 [2] 9d c9 [2] 9f c8 [2] 84 ce [2] 98 c9 [2] 84 e6 }

  condition:
    any of them
}