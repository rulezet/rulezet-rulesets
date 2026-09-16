rule TTP_XOR_QUAD_CurrentVersionRun_c9ba {
  strings:
    $key_c9ba = { 9a d5 [2] be db [2] 95 f7 [2] bb d5 [2] af ce [2] a0 d4 [2] be c9 [2] bc c8 [2] a7 ce [2] bb c9 [2] a7 e6 }

  condition:
    any of them
}