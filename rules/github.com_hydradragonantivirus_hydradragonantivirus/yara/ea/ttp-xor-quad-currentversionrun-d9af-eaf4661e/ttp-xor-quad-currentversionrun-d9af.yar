rule TTP_XOR_QUAD_CurrentVersionRun_d9af {
  strings:
    $key_d9af = { 8a c0 [2] ae ce [2] 85 e2 [2] ab c0 [2] bf db [2] b0 c1 [2] ae dc [2] ac dd [2] b7 db [2] ab dc [2] b7 f3 }

  condition:
    any of them
}