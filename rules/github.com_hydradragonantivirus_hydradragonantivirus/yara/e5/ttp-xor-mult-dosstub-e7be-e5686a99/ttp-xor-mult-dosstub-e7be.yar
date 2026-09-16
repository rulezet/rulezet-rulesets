rule TTP_XOR_MULT_DOSStub_e7be {
  strings:
    $key_e7be = { b3 d6 [2] c7 ce [2] 80 cc [2] c7 dd [2] 89 d1 [2] 85 db [2] 92 d0 [2] 89 9e [2] b4 }

  condition:
    any of them
}