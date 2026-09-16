rule TTP_XOR_QUAD_CurrentVersionRun_d7ba {
  strings:
    $key_d7ba = { 84 d5 [2] a0 db [2] 8b f7 [2] a5 d5 [2] b1 ce [2] be d4 [2] a0 c9 [2] a2 c8 [2] b9 ce [2] a5 c9 [2] b9 e6 }

  condition:
    any of them
}