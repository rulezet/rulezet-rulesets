rule TTP_XOR_MULT_DOSStub_3bbe {
  strings:
    $key_3bbe = { 6f d6 [2] 1b ce [2] 5c cc [2] 1b dd [2] 55 d1 [2] 59 db [2] 4e d0 [2] 55 9e [2] 68 }

  condition:
    any of them
}