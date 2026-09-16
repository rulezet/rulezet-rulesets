rule TTP_XOR_QUAD_CurrentVersionRun_c2af {
  strings:
    $key_c2af = { 91 c0 [2] b5 ce [2] 9e e2 [2] b0 c0 [2] a4 db [2] ab c1 [2] b5 dc [2] b7 dd [2] ac db [2] b0 dc [2] ac f3 }

  condition:
    any of them
}