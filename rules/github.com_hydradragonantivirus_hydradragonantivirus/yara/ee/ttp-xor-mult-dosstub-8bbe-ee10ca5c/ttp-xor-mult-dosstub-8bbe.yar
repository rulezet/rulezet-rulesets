rule TTP_XOR_MULT_DOSStub_8bbe {
  strings:
    $key_8bbe = { df d6 [2] ab ce [2] ec cc [2] ab dd [2] e5 d1 [2] e9 db [2] fe d0 [2] e5 9e [2] d8 }

  condition:
    any of them
}