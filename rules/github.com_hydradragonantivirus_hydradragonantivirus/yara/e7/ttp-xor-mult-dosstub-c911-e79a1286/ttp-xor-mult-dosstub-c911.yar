rule TTP_XOR_MULT_DOSStub_c911 {
  strings:
    $key_c911 = { 9d 79 [2] e9 61 [2] ae 63 [2] e9 72 [2] a7 7e [2] ab 74 [2] bc 7f [2] a7 31 [2] 9a }

  condition:
    any of them
}