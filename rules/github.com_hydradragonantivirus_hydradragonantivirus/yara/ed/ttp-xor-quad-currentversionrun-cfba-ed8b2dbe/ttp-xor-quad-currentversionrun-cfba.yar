rule TTP_XOR_QUAD_CurrentVersionRun_cfba {
  strings:
    $key_cfba = { 9c d5 [2] b8 db [2] 93 f7 [2] bd d5 [2] a9 ce [2] a6 d4 [2] b8 c9 [2] ba c8 [2] a1 ce [2] bd c9 [2] a1 e6 }

  condition:
    any of them
}