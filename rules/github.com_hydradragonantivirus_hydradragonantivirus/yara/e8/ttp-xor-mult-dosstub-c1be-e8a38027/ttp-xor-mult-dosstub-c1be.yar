rule TTP_XOR_MULT_DOSStub_c1be {
  strings:
    $key_c1be = { 95 d6 [2] e1 ce [2] a6 cc [2] e1 dd [2] af d1 [2] a3 db [2] b4 d0 [2] af 9e [2] 92 }

  condition:
    any of them
}