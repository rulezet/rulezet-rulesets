rule TTP_XOR_MULT_DOSStub_c932 {
  strings:
    $key_c932 = { 9d 5a [2] e9 42 [2] ae 40 [2] e9 51 [2] a7 5d [2] ab 57 [2] bc 5c [2] a7 12 [2] 9a }

  condition:
    any of them
}