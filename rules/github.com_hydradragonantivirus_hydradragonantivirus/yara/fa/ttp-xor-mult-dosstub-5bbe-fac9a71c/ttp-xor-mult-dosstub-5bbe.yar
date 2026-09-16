rule TTP_XOR_MULT_DOSStub_5bbe {
  strings:
    $key_5bbe = { 0f d6 [2] 7b ce [2] 3c cc [2] 7b dd [2] 35 d1 [2] 39 db [2] 2e d0 [2] 35 9e [2] 08 }

  condition:
    any of them
}