rule TTP_XOR_QUAD_CurrentVersionRun_c9af {
  strings:
    $key_c9af = { 9a c0 [2] be ce [2] 95 e2 [2] bb c0 [2] af db [2] a0 c1 [2] be dc [2] bc dd [2] a7 db [2] bb dc [2] a7 f3 }

  condition:
    any of them
}