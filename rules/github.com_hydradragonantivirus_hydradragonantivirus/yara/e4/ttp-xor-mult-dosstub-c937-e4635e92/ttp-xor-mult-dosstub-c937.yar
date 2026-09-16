rule TTP_XOR_MULT_DOSStub_c937 {
  strings:
    $key_c937 = { 9d 5f [2] e9 47 [2] ae 45 [2] e9 54 [2] a7 58 [2] ab 52 [2] bc 59 [2] a7 17 [2] 9a }

  condition:
    any of them
}