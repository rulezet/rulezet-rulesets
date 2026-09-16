rule TTP_XOR_MULT_DOSStub_c9e7 {
  strings:
    $key_c9e7 = { 9d 8f [2] e9 97 [2] ae 95 [2] e9 84 [2] a7 88 [2] ab 82 [2] bc 89 [2] a7 c7 [2] 9a }

  condition:
    any of them
}