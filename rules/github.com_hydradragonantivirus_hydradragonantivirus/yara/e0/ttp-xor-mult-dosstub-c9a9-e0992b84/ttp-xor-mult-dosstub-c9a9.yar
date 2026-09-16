rule TTP_XOR_MULT_DOSStub_c9a9 {
  strings:
    $key_c9a9 = { 9d c1 [2] e9 d9 [2] ae db [2] e9 ca [2] a7 c6 [2] ab cc [2] bc c7 [2] a7 89 [2] 9a }

  condition:
    any of them
}