rule TTP_XOR_MULT_DOSStub_c930 {
  strings:
    $key_c930 = { 9d 58 [2] e9 40 [2] ae 42 [2] e9 53 [2] a7 5f [2] ab 55 [2] bc 5e [2] a7 10 [2] 9a }

  condition:
    any of them
}