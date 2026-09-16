rule TTP_XOR_MULT_DOSStub_33be {
  strings:
    $key_33be = { 67 d6 [2] 13 ce [2] 54 cc [2] 13 dd [2] 5d d1 [2] 51 db [2] 46 d0 [2] 5d 9e [2] 60 }

  condition:
    any of them
}