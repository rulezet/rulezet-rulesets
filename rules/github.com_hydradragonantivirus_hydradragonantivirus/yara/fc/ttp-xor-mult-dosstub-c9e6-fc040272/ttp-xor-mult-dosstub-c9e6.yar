rule TTP_XOR_MULT_DOSStub_c9e6 {
  strings:
    $key_c9e6 = { 9d 8e [2] e9 96 [2] ae 94 [2] e9 85 [2] a7 89 [2] ab 83 [2] bc 88 [2] a7 c6 [2] 9a }

  condition:
    any of them
}